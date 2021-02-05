#!/usr/bin/python3
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2021 Frédéric Pierret (fepitre) <frederic.pierret@qubes-os.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse
import dnf
import dnf.conf
import grp
import koji
import logging
import os
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import xml
import xmltodict

from dateutil.parser import parse as parsedate
from debian.deb822 import Deb822
from libs.openpgp import OpenPGPEnvironment, OpenPGPException

logger = logging.getLogger('rpmreproduce')
console_handler = logging.StreamHandler(sys.stderr)
logger.addHandler(console_handler)


class PackageException(Exception):
    pass


class BuildInfoException(Exception):
    pass


class RebuilderException(Exception):
    pass


def parsePkg(pkg):
    pkg = pkg.strip()
    if koji.check_NVRA(pkg):
        pkg = koji.parse_NVRA(pkg)
        return Package(**pkg)


class Package:
    def __init__(self, name, version, release, arch, epoch, **kwargs):
        self.name = name
        self.version = version
        self.release = release
        self.arch = arch
        self.epoch = epoch
        self.source_name = kwargs.get("source_name", None)
        self.url = kwargs.get("url", None)

    def to_nvr(self):
        if self.epoch:
            result = "{}:{}-{}-{}".format(
                self.epoch, self.name, self.version, self.release)
        else:
            result = "{}-{}-{}".format(self.name, self.version, self.release)
        return result

    def to_rpmfname(self):
        result = "{}-{}-{}.{}.rpm".format(
            self.name, self.version, self.release, self.arch)
        return result

    def to_dict(self):
        return self.__dict__

    def __repr__(self):
        if self.epoch:
            result = "{}:{}-{}-{}.{}".format(
                self.epoch, self.name, self.version, self.release, self.arch)
        else:
            result = "{}-{}-{}.{}".format(
                self.name, self.version, self.release, self.arch)
        return result


class BuildInfo:
    def __init__(self, buildinfo_file):
        self.orig_file = buildinfo_file

        self.source = None
        self.architecture = None
        self.binary = None
        self.version = None
        self.build_path = None
        self.build_arch = None
        self.build_date = None
        self.host_arch = None
        self.checksums = {}
        self.build_depends = []
        self.env = {}

        self.required_timestamps = []
        self.fedora_release = None

        if not os.path.exists(self.orig_file):
            raise BuildInfoException(
                "Cannot find buildinfo file: {}".format(self.orig_file))

        with open(self.orig_file) as fd:
            for paragraph in Deb822.iter_paragraphs(fd.read()):
                for item in paragraph.items():
                    if item[0] == 'Source':
                        self.source = item[1]
                    if item[0] == 'Architecture':
                        self.architecture = item[1].split()
                    if item[0] == 'Binary':
                        self.binary = item[1].split()
                    if item[0] == 'Version':
                        self.version = item[1]
                    if item[0] == 'Build-Path':
                        self.build_path = item[1]
                    if item[0] == 'Build-Architecture':
                        self.build_arch = item[1]
                    if item[0] == 'Build-Date':
                        self.build_date = item[1]
                    if item[0] == 'Host-Architecture':
                        self.host_arch = item[1]
                    if item[0].startswith('Checksums-'):
                        alg = item[0].replace('Checksums-', '').lower()
                        for line in item[1].lstrip('\n').split('\n'):
                            parsed_line = line.split()
                            if not self.checksums.get(parsed_line[2], {}):
                                self.checksums[parsed_line[2]] = {}
                            self.checksums[parsed_line[2]].update({
                                "size": parsed_line[1],
                                alg: parsed_line[0],
                            })
                    if item[0] == 'Installed-Build-Depends':
                        for pkg in item[1].lstrip('\n').split('\n'):
                            if pkg.endswith('.(none)'):
                                continue
                            parsed_pkg = parsePkg(pkg)
                            if not parsed_pkg:
                                raise BuildInfoException(
                                    "Cannot parse package: %s" % pkg)
                            self.build_depends.append(parsed_pkg)
                    if item[0] == 'Environment':
                        for line in item[1].lstrip('\n').split('\n'):
                            parsed_line = re.match(r'^[^=](.*)="(.*)"', line)
                            if parsed_line:
                                self.env[parsed_line.group(1).strip()] = \
                                    parsed_line.group(2).strip()

        self.build_source = len(
            [arch for arch in self.architecture if arch == "src"]) == 1
        self.build_archall = len(
            [arch for arch in self.architecture if arch == "noarch"]) == 1
        self.architecture = [
            arch for arch in self.architecture if arch != "noarch"]

        if len(self.architecture) > 1:
            raise BuildInfoException(
                "More than one architecture in Architecture field")

        if not self.build_arch:
            raise BuildInfoException("Need Build-Architecture field")
        if not self.host_arch:
            self.host_arch = self.build_arch
        if not self.build_path:
            self.build_path = "/build/{}-{}".format(
                self.source, next(tempfile._get_candidate_names()))

        self.package = parsePkg('{}-{}.src'.format(self.source, self.version))

    def __repr__(self):
        return f'{self.source}-{self.version}'

    def get_fedora_release(self):
        if not self.fedora_release:
            for pkg in self.get_build_depends():
                if str(pkg.name) == "fedora-release":
                    self.fedora_release = pkg.version
            if not self.fedora_release:
                raise BuildInfoException("Cannot determine Fedora release")
        return self.fedora_release

    def get_fedora_keyfile(self):
        key = "tests/keys/RPM-GPG-KEY-fedora-{}-primary".format(
            self.get_fedora_release())
        return os.path.join(os.path.dirname(__file__), key)

    def get_fedora_keyid(self):
        gpg_env = OpenPGPEnvironment()
        try:
            gpg_env.import_key(self.get_fedora_keyfile())
            keyid = gpg_env.list_keys()[0].lower()
        except (OpenPGPException, KeyError):
            raise BuildInfoException("Cannot determine Fedora keyid")
        finally:
            gpg_env.close()
        return keyid[-8:]

    def get_build_depends(self):
        return self.build_depends

    def get_build_date(self):
        try:
            return parsedate(self.build_date).strftime(
                "%Y%m%dT%H%M%SZ")
        except ValueError as e:
            raise RebuilderException("Cannot parse 'Build-Date': %s" % e)


class Rebuilder:
    def __init__(self, buildinfo_file,
                 extra_repository_files=None, extra_repository_keys=None,
                 gpg_sign_keyid=None,
                 gpg_verify=False,
                 gpg_verify_key=None,
                 proxy=None):
        self.buildinfo = None
        self.extra_repository_files = extra_repository_files
        self.extra_repository_keys = extra_repository_keys
        self.gpg_sign_keyid = gpg_sign_keyid
        self.proxy = proxy
        self.session = requests.Session()
        self.session.proxies = {
            "http:": self.proxy,
            "https": self.proxy
        }

        self.required_rpms = []
        self.tempdnfdir = None
        self.tempdnfcache = None

        self.tmpdir = os.environ.get('TMPDIR', '/tmp')
        self.cachedir = os.environ.get('CACHEDIR', os.path.join(
            self.tmpdir, 'rpmreproduce/cache'))

        self.urlsdir = os.path.join(self.cachedir, 'urls')
        self.rpmsdir = os.path.join(self.cachedir, 'rpms')
        self.srpmsdir = os.path.join(self.cachedir, 'srpms')

        if buildinfo_file.startswith('http://') or \
                buildinfo_file.startswith('https://'):
            try:
                resp = self.get_response(buildinfo_file)
                resp.raise_for_status()
                # We store remote buildinfo in a temporary file
                handle, buildinfo_file = tempfile.mkstemp(
                    prefix="buildinfo-", dir=self.tmpdir)
                with open(handle, 'w') as fd:
                    fd.write(resp.text)
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.HTTPError) as e:
                raise RebuilderException("Cannot get buildinfo: {}".format(e))
        else:
            buildinfo_file = realpath(buildinfo_file)

        if gpg_verify and gpg_verify_key:
            gpg_env = OpenPGPEnvironment()
            try:
                gpg_env.import_key(gpg_verify_key, trust=True)
                gpg_env.verify_file(buildinfo_file)
            except OpenPGPException as e:
                raise RebuilderException(
                    "Failed to verify buildinfo: {}".format(str(e)))
            finally:
                gpg_env.close()

        self.buildinfo = BuildInfo(buildinfo_file)
        if buildinfo_file.startswith(
                os.path.join(self.tmpdir, 'buildinfo-')):
            os.remove(buildinfo_file)

    def get_env(self):
        env = []
        for key, val in self.buildinfo.env.items():
            env.append("{}=\"{}\"".format(key, val))
        return env

    def get_response(self, url):
        retries = 3
        while retries:
            try:
                resp = self.session.get(url)
                return resp
            except requests.exceptions.ConnectionError:
                logger.debug("Retry to get url: {}".format(url))
                retries -= 1
        raise RebuilderException("Failed to get response: max retries")

    def download(self, url, dst):
        if os.path.exists(dst):
            logger.debug("Already downloaded: {}".format(url))
        else:
            logger.debug("Downloading {} to {}".format(url, dst))
        resp = self.get_response(url)
        if resp.ok:
            with open(dst, 'wb') as fd:
                fd.write(resp.content)
        else:
            raise RebuilderException("Cannot download: {}".format(url))

    def get_comps(self):
        baseurl = "https://dl.fedoraproject.org/pub/fedora/linux/" \
                  "releases/{}/Everything/x86_64/os/".format(
            self.buildinfo.get_fedora_release())
        url = os.path.join(baseurl, "repodata/repomd.xml")
        comps = os.path.join(self.cachedir, "comps-fc{}.xml".format(
            self.buildinfo.get_fedora_release()))
        # Check if we already have a local copy of comps
        if os.path.exists(comps):
            return comps
        resp = self.get_response(url)
        try:
            items = xmltodict.parse(resp.text)["repomd"]["data"]
            for item in items:
                if item["@type"] == "group":
                    rurl = item["location"]["@href"]
                    url = os.path.join(baseurl, rurl)
                    if re.search("-(comps-.+?.xml)", url):
                        with open(comps, "w") as fd:
                            fd.write(self.get_response(url).text)
                        return comps
        except xml.parsers.expat.ExpatError as e:
            raise RebuilderException("Cannot get comps file: {}".format(e))

    def prepare_dnfcache(self):
        self.tempdnfdir = tempfile.mkdtemp(
            prefix="rpmreproduce-dnf-", dir=self.tmpdir)

        cachedir = os.path.join(self.tempdnfdir, 'cache')
        installroot = os.path.join(self.tempdnfdir, 'installroot')
        reposdir = os.path.join(self.tempdnfdir, 'repos')
        os.makedirs(cachedir)
        os.makedirs(installroot)
        os.makedirs(reposdir)

        base = dnf.Base()
        base.conf.cachedir = cachedir
        base.conf.installroot = installroot
        base.conf.substitutions['releasever'] = \
            self.buildinfo.get_fedora_release()
        base.conf.reposdir = []
        base.read_comps(arch_filter=True)

        if self.extra_repository_files:
            for repo_src in self.extra_repository_files:
                repo_dst = os.path.join(reposdir, os.path.basename(repo_src))
                os.symlink(repo_src, repo_dst)

        base.conf.reposdir = os.path.join(self.tempdnfdir, 'repos')
        base.read_all_repos()
        base.fill_sack()

        query = base.sack.query
        self.tempdnfcache = {}
        for rpm in set(query()):
            pkg = Package(rpm.name, rpm.version, rpm.release, rpm.arch,
                          rpm.epoch, source_name=rpm.source_name,
                          url=rpm.remote_location())
            self.tempdnfcache[str(pkg)] = pkg

    def refresh_package(self, package):
        if self.tempdnfcache.get(str(package), None):
            # TODO: better handling of multiple properties
            package.url = self.tempdnfcache[str(package)].url
            package.source_name = self.tempdnfcache[str(package)].source_name
            return

        kojicli = koji.ClientSession('https://koji.fedoraproject.org/kojihub')
        pathinfo = koji.PathInfo('https://kojipkgs.fedoraproject.org')

        # TODO: We need to ensure to get signed package from koji, either by
        #  direct download or by reconstructed RPM with detached signature
        rpmfname = pathinfo.signed(
            package.to_dict(), self.buildinfo.get_fedora_keyid())
        rpminfo = kojicli.getRPM(package.to_rpmfname())
        if not rpmfname or not rpminfo:
            return
        # we need to determinate the source package for the baseurl
        if not rpminfo.get('buildroot_id', None):
            return
        buildroot = kojicli.getBuildroot(rpminfo['buildroot_id'])
        task = kojicli.getTaskInfo(buildroot['task_id'], request=True)
        # tasks/6906/41136906/chkconfig-1.11-6.fc32.src.rpm
        srcpkg = parsePkg(task['request'][0].split('/')[-1])
        if not srcpkg:
            return
        rpmurl = os.path.join(pathinfo.build(srcpkg.to_dict()), rpmfname)
        if self.get_response(rpmurl).ok:
            package.url = rpmurl

    @staticmethod
    def get_rpm_sign_keyid(rpmfname):
        try:
            sighdr = koji.rip_rpm_sighdr(rpmfname)
            sigkeyid = koji.get_sighdr_key(sighdr).upper()
            return sigkeyid
        except koji.GenericError as e:
            raise RebuilderException(
                "Failed to get RPM signature keyid: {}".format(str(e)))

    def get_build_dependencies(self):
        flist = os.path.join(self.urlsdir, "{}.list".format(self.buildinfo))
        os.makedirs(self.urlsdir, exist_ok=True)

        urls = []
        # Check if we already have a local copy of urls
        if os.path.exists(flist):
            with open(flist) as fd:
                urls = fd.read().strip('\n').split('\n')
        else:
            for builddep in self.buildinfo.build_depends:
                logger.debug(
                    "Fetching build dependency url: {}".format(builddep))
                self.refresh_package(builddep)
                if not builddep.url:
                    raise RebuilderException(
                        "Cannot get url: {}".format(builddep))
                urls.append(builddep.url)

            # We create a local copy of fetched URL in case of retry
            with open(flist, "w") as fd:
                fd.write('\n'.join(urls))

        # TODO: refactor/improve notably exception
        # Download RPMs
        gpg_env = OpenPGPEnvironment()
        try:
            gpg_env.import_key(self.buildinfo.get_fedora_keyfile())
            for key in self.extra_repository_keys:
                gpg_env.import_key(key)

            # short keyid format
            allowed_keys = [key[-8:] for key in gpg_env.list_keys()]
            os.makedirs(self.rpmsdir, exist_ok=True)
            for rpmurl in urls:
                rpmfname = os.path.join(self.rpmsdir, os.path.basename(rpmurl))
                self.required_rpms.append(rpmfname)
                self.download(rpmurl, rpmfname)
                if self.get_rpm_sign_keyid(rpmfname) not in allowed_keys:
                    raise RebuilderException(
                        "Failed to verify RPM signature: {}".format(rpmfname))
        except RebuilderException as e:
            raise RebuilderException(str(e))
        except OpenPGPException as e:
            raise RebuilderException(
                "Failed to prepare GPG env: {}".format(str(e)))
        finally:
            gpg_env.close()

    def generate_local_repository(self, output):
        # Create local repository
        localrepo = os.path.join(output, "local")
        os.makedirs(localrepo)
        for rpm in self.required_rpms:
            shutil.copy2(rpm, localrepo)

        # TODO: use python lib
        createrepo_cmd = [
            "createrepo", "-g", "{}".format(self.get_comps()), "."
        ]
        try:
            subprocess.run(createrepo_cmd, cwd=localrepo, check=True)
        except subprocess.CalledProcessError as e:
            raise RebuilderException(
                "Failed to create local repository: {}".format(str(e)))

    def get_source_rpm(self):
        src_pkg = self.buildinfo.package
        self.refresh_package(src_pkg)

        os.makedirs(self.srpmsdir, exist_ok=True)
        src_rpm = os.path.join(self.srpmsdir, src_pkg.to_rpmfname())
        if not os.path.exists(src_rpm):
            self.download(src_pkg.url, src_rpm)

    def gen_mock_config(self, output):
        localrepo = os.path.join(output, "local")
        mock_config_file = os.path.join(output, 'mock.cfg')
        mock_config = """
config_opts['basedir'] = '{builddir}/mock'
config_opts['use_bootstrap'] = False

config_opts['root'] = 'fedora-{releasever}-x86_64'
config_opts['target_arch'] = 'x86_64'
config_opts['legal_host_arches'] = ('x86_64',)
config_opts['chroot_setup_cmd'] = 'install @buildsys-build'
config_opts['dist'] = 'fc{releasever}'
config_opts['extra_chroot_dirs'] = [ '/run/lock', ]
config_opts['releasever'] = {releasever}
config_opts['package_manager'] = 'dnf'
config_opts['nosync'] = True
config_opts['nosync_force'] = True
config_opts['macros']['source_date_epoch_from_changelog'] = 'Y'
config_opts['macros']['clamp_mtime_to_source_date_epoch'] = 'Y'
config_opts['macros']['use_source_date_epoch_as_buildtime'] = 'Y'
config_opts['macros']['_buildhost'] = 'reproducible'

config_opts['yum.conf'] = \"\"\"
[main]
keepcache=1
debuglevel=2
reposdir=/dev/null
logfile=/var/log/yum.log
retries=20
obsoletes=1
gpgcheck=0
assumeyes=1
syslog_ident=mock
syslog_device=
install_weak_deps=0
metadata_expire=0
mdpolicy=group:primary
best=1

[local]
name=local
baseurl=file://{localrepo}
cost=2000
enabled=1

\"\"\"
""".format(localrepo=localrepo, releasever=self.buildinfo.get_fedora_release(),
           builddir=output)
        with open(mock_config_file, 'w') as fd:
            fd.write(mock_config)

    def mock(self, output, new_buildinfo_file):
        self.gen_mock_config(output)
        # rebuild
        cmd = [
            'env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'mock', '--no-cleanup-after',
            '-r', os.path.join(output, 'mock.cfg'),
            '--resultdir', output,
            '--rebuild', os.path.join(
                self.srpmsdir, self.buildinfo.package.to_rpmfname())
        ]
        logger.debug(' '.join(cmd))
        subprocess.run(cmd, check=True)

        # create buildinfo
        cmd = [
            'env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'mock', '-q', '-r', os.path.join(output, 'mock.cfg'),
            '--plugin-option=bind_mount:dirs=[("{}", "/scripts")]'.format(
                os.path.join(os.path.dirname(__file__), 'scripts')), '--chroot',
            '/scripts/rpmbuildinfo /builddir/build/SRPMS/{}'.format(
                self.buildinfo.package.to_rpmfname())
        ]
        logger.debug(' '.join(cmd))
        subprocess.run(cmd, check=True)

        # copy buildinfo to output
        # TODO: check why chaining --chroot and --copyout has issue with paths
        cmd = [
            'env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'mock', '-q', '-r', os.path.join(output, 'mock.cfg'), '--copyout',
            '/builddir/build/SRPMS/{}'.format(
                os.path.basename(new_buildinfo_file)),
            '{}'.format(output)
        ]
        logger.debug(' '.join(cmd))
        subprocess.run(cmd, check=True)

        # cleanup
        cmd = [
            'env', '-i', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin',
            'mock', '-q', '-r', os.path.join(output, 'mock.cfg'), '--clean'
        ]
        logger.debug(' '.join(cmd))
        subprocess.run(cmd, check=True)

    def verify_checksums(self, new_buildinfo):
        files = [f for f in self.buildinfo.checksums.keys() if
                 not f.endswith('.dsc')]
        new_files = new_buildinfo.checksums.keys()

        if len(files) != len(new_files):
            logger.debug("old buildinfo: {}".format(' '.join(files)))
            logger.debug("new buildinfo: {}".format(' '.join(new_files)))
            raise RebuilderException(
                "New buildinfo contains a different number of files")

        status = True
        for f in files:
            cur_status = True
            for prop in self.buildinfo.checksums[f].keys():
                if prop == "size":
                    f_size = self.buildinfo.checksums[f]["size"]
                    if f_size != new_buildinfo.checksums[f]["size"]:
                        logger.error("Size differs for {}".format(f))
                        # logger.debug("{} size: {}".format(f, f_size))
                        cur_status = False
                if prop not in new_buildinfo.checksums[f].keys():
                    raise RebuilderException(
                        "{} is not used in both buildinfo files".format(prop))
                if self.buildinfo.checksums[f][prop] != \
                        new_buildinfo.checksums[f][prop]:
                    logger.error("Value of {} differs for {}".format(prop, f))
                    cur_status = False
            if cur_status:
                logger.info("{}: OK".format(f))
            else:
                status = False

        if not status:
            raise RebuilderException

    def generate_intoto_metadata(self, output, new_buildinfo):
        new_files = new_buildinfo.checksums.keys()
        cmd = ["in-toto-run", "--step-name=rebuild", "--no-command",
               "--products"] + list(new_files)
        if self.gpg_sign_keyid:
            cmd += ["--gpg", self.gpg_sign_keyid]
        else:
            cmd += ["--gpg"]
        if subprocess.run(cmd, cwd=output).returncode != 0:
            raise RebuilderException("in-toto metadata generation failed")
        logger.info("in-toto metadata generation: OK")

    @staticmethod
    def get_host_architecture():
        try:
            builder_architecture = subprocess.check_output(
                ["uname", "--m"]).decode('utf8').rstrip('\n')
        except FileNotFoundError:
            raise RebuilderException(
                "Cannot determinate builder host architecture")
        return builder_architecture

    def run(self, builder, output, no_checksums_verification=False):
        # Predict new buildinfo name created by builder
        # Based on dpkg/scripts/dpkg-genbuildinfo.pl
        if self.buildinfo.architecture:
            build_arch = self.get_host_architecture()
        elif self.buildinfo.build_archall:
            build_arch = "noarch"
        else:
            raise RebuilderException("Nothing to build")

        new_buildinfo_file = "{}/{}-{}.{}.buildinfo".format(
            output, self.buildinfo.source, self.buildinfo.version, build_arch)
        logger.debug("New buildinfo file: {}".format(new_buildinfo_file))
        if os.path.exists(new_buildinfo_file):
            raise RebuilderException(
                "Refusing to overwrite existing buildinfo file")

        # Stage 1: Parse provided buildinfo file and setup the rebuilder
        try:
            os.makedirs(output, exist_ok=True)
            self.prepare_dnfcache()
            self.get_build_dependencies()
            self.get_source_rpm()
            self.generate_local_repository(output)
        except (FileExistsError, requests.exceptions.ConnectionError) as e:
            raise RebuilderException(
                "Failed to prepare rebuild: {}".format(str(e)))
        except KeyboardInterrupt:
            raise RebuilderException("Interruption")
        finally:
            if self.tempdnfdir and self.tempdnfdir.startswith(
                    os.path.join(self.tmpdir, 'rpmreproduce-dnf-')):
                shutil.rmtree(self.tempdnfdir)

        # Stage 2: Run the actual rebuild of provided buildinfo file
        if builder == "none":
            return
        if builder == "mock":
            try:
                self.mock(output, new_buildinfo_file)
            except subprocess.CalledProcessError as e:
                RebuilderException("mock failed: {}".format(str(e)))

        # Stage 3: Everything post-build actions with rebuild artifacts
        new_buildinfo = BuildInfo(realpath(new_buildinfo_file))
        try:
            self.verify_checksums(new_buildinfo)
            logger.info("Checksums: OK")
        except RebuilderException:
            msg = "Checksums: FAIL"
            if no_checksums_verification:
                logger.error(msg)
            else:
                raise RebuilderException(msg)
        self.generate_intoto_metadata(output, new_buildinfo)


def get_args():
    parser = argparse.ArgumentParser(
        description='Given a buildinfo file from a RPM package, '
                    'generate instructions for attempting to reproduce '
                    'the binary packages built from the associated source '
                    'and build information.'
    )
    parser.add_argument(
        "buildinfo",
        help="Input buildinfo file. Local or remote file."
    )
    parser.add_argument(
        "--output",
        help="Directory for the build artifacts",
    )
    parser.add_argument(
        "--builder",
        help="Which building software should be used. (default: none)",
        default="none"
    )
    parser.add_argument(
        "--extra-repository-file",
        help="Add repository file content to the list of apt sources during "
             "the package build.",
        action="append"
    )
    parser.add_argument(
        "--extra-repository-key",
        help="Add key file (.asc) to the list of trusted keys during "
             "the package build.",
        action="append"
    )
    parser.add_argument(
        "--gpg-sign-keyid",
        help="GPG keyid to use for signing in-toto metadata."
    )
    parser.add_argument(
        "--gpg-verify",
        help="Verify buildinfo GPG signature.",
        action="store_true"
    )
    parser.add_argument(
        "--gpg-verify-key",
        help="GPG key to use for buildinfo GPG check.",
    )
    parser.add_argument(
        "--proxy",
        help="Proxy address to use."
    )
    parser.add_argument(
        "--no-checksums-verification",
        help="Don't fail on checksums verification between original and"
             " rebuild packages",
        action="store_true",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Display logger info messages."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Display logger debug messages."
    )
    return parser.parse_args()


def realpath(path):
    return os.path.abspath(os.path.expanduser(path))


def main():
    args = get_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.ERROR)

    if args.builder not in ("none", "mock"):
        logger.error("Unknown builder: {}".format(args.builder))
        return 1

    user_groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
    if args.builder == "mock":
        if "mock" not in user_groups:
            logger.error("Cannot user 'mock' builder. Current user is "
                         "not in 'mock' group")
            return 1
        # TODO: sanity check for "dev" option on OUTPUT

    if args.gpg_verify_key:
        args.gpg_verify_key = realpath(args.gpg_verify_key)

    if args.extra_repository_file:
        args.extra_repository_file = \
            [realpath(repo_file) for repo_file in args.extra_repository_file]

    if args.extra_repository_key:
        args.extra_repository_key = \
            [realpath(key_file) for key_file in args.extra_repository_key]

    if args.gpg_verify and not args.gpg_verify_key:
        logger.error(
            "Cannot verify buildinfo signature without GPG keyring provided")
        return 1

    try:
        rebuilder = Rebuilder(
            buildinfo_file=args.buildinfo,
            extra_repository_files=args.extra_repository_file,
            extra_repository_keys=args.extra_repository_key,
            gpg_sign_keyid=args.gpg_sign_keyid,
            gpg_verify=args.gpg_verify,
            gpg_verify_key=args.gpg_verify_key,
            proxy=args.proxy
        )
        rebuilder.run(builder=args.builder, output=realpath(args.output),
                      no_checksums_verification=args.no_checksums_verification)
    except RebuilderException as e:
        logger.error(str(e))
        return 1


if __name__ == "__main__":
    sys.exit(main())
