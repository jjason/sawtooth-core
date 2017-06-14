# Copyright 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import os
import shutil
import subprocess
import sys
import sysconfig

from setuptools import setup, Extension, find_packages
from distutils.command import build as build_module
from shutil import copyfile

script_dir = os.path.dirname(os.path.realpath(__file__))


def bump_version(version):
    (major, minor, patch) = version.split('.')
    patch = str(int(patch) + 1)
    return ".".join([major, minor, patch])


def auto_version(default, strict):
    output = subprocess.check_output(['git', 'describe', '--dirty'])
    parts = output.strip().split('-', 1)
    parts[0] = parts[0][1:]  # strip the leading 'v'
    if len(parts) == 2:
        parts[0] = bump_version(parts[0])
    if default != parts[0]:
        msg = "setup.py and (bumped?) git describe versions differ: {} != {}"\
            .format(
                default, parts[0])
        if strict:
            print('ERROR: {}'.format(msg), file=sys.stderr)
            sys.exit(1)
        else:
            print('WARNING: {}'.format(msg), file=sys.stderr)
            print('WARNING: using setup.py version {}'.format(
                default),
                file=sys.stderr)
            parts[0] = default

    if len(parts) == 2:
        return "-git".join([parts[0], parts[1].replace("-", ".")])
    else:
        return parts[0]


def version(default):
    if 'VERSION' in os.environ:
        if os.environ['VERSION'] == 'AUTO_STRICT':
            version = auto_version(default, strict=True)
        elif os.environ['VERSION'] == 'AUTO':
            version = auto_version(default, strict=False)
        else:
            version = os.environ['VERSION']
    else:
        version = default + "-dev1"
    return version


if os.name == 'nt':
    platform_dir = 'windows'
    package_data = []

    ext_deps = ['deps/bin/libpoet.dll',
                'deps/bin/libpoet-enclave.signed.dll',
                'deps/bin/msvcp110.dll',
                'deps/bin/msvcr110.dll']
    for f in ext_deps:
        package_data.append(os.path.basename(f))
    extra_compile_args = ['/EHsc']
    libraries = ['json-c', 'cryptopp-static', 'libpoet']
    include_dirs = ['deps/include']

else:
    platform_dir = 'linux'
    extra_compile_args = ['-std=c++11']
    libraries = ['json-c', 'crypto++', 'poet']
    ext_deps = ['deps/bin/libpoet.so',
                'deps/bin/libpoet-enclave.signed.so']
    package_data = []
    include_dirs = []

include_dirs += ['poet_enclave_sgx',
                 'poet_enclave_sgx/{}'.format(platform_dir),
                 'libpoet_shared',
                 'libpoet_shared/{}'.format(platform_dir)]
library_dirs = ['deps/lib']

enclavemod = Extension('_poet_enclave',
                       ['poet_enclave_sgx/poet_enclave.i',
                        'poet_enclave_sgx/common.cpp',
                        'poet_enclave_sgx/poet.cpp',
                        'poet_enclave_sgx/wait_certificate.cpp',
                        'poet_enclave_sgx/wait_timer.cpp',
                        'poet_enclave_sgx/signup_data.cpp',
                        'poet_enclave_sgx/signup_info.cpp',
                        'libpoet_shared/{}/c11_support.cpp'.format(
                            platform_dir),
                        'poet_enclave_sgx/{}/platform_support.cpp'.format(
                            platform_dir)
                        ],
                       swig_opts=['-c++'],
                       extra_compile_args=extra_compile_args,
                       include_dirs=include_dirs,
                       libraries=libraries,
                       library_dirs=library_dirs)


class Build(build_module.build):
    def build_poet(self):
        print('Building PoET SGX module')
        if not os.path.exists("build"):
            os.mkdir("build")
        os.chdir("build")

        if os.name == 'nt':
            args = ["-G", "Visual Studio 11 2012 Win64"]
        else:
            args = ["-G", "Unix Makefiles"]

        subprocess.call(["cmake", ".."] + args)

        if os.name == 'nt':
            args = ["--config", "Release"]
        else:
            args = []

        subprocess.call(["cmake", "--build", "."] + args)

        os.chdir("..")

        for fl in ext_deps:
            dst = os.path.join(script_dir, os.path.basename(fl))
            copyfile(fl, dst)
            package_data.append(os.path.basename(fl))

    def run(self):
        self.build_poet()
        build_module.build.run(self)

if os.name == 'nt':
    conf_dir = "C:\\Program Files (x86)\\Intel\\sawtooth\\conf"
else:
    conf_dir = "/etc/sawtooth"

setup(name='sawtooth-poet',
      version=version('0.8.4'),
      description='Sawtooth Lake PoET SGX Enclave',
      author='Intel Corporation',
      url='http://www.intel.com',
      packages=find_packages(),
      install_requires=[
          'toml',
          'ecdsa',
          'sawtooth-poet-common',
          'satooth-signing'
          ],
      ext_modules=[enclavemod],
      py_modules=['poet_enclave_sgx.poet_enclave'],
      data_files=[
          ('lib', package_data),
          (conf_dir, ['packaging/ias_rk_pub.pem',
                      'packaging/poet_enclave_sgx.toml.example'])],
      cmdclass={'build': Build},
      entry_points={}
      )

if "clean" in sys.argv and "--all" in sys.argv:
    directory = os.path.dirname(os.path.realpath(__file__))
    for root, fn_dir, files in os.walk(directory):
        for fn in files:
            if fn.endswith(".pyc"):
                os.remove(os.path.join(root, fn))
    for filename in [".coverage",
                     "_poet_enclave{}".format(
                         sysconfig.get_config_var('EXT_SUFFIX')),
                     os.path.join("poet_enclave_sgx", "poet_enclave.py"),
                     os.path.join("poet_enclave_sgx", "_poet_enclave.cpp"),
                     "nose2-junit.xml"]:
        if os.path.exists(os.path.join(directory, filename)):
            os.remove(os.path.join(directory, filename))
    shutil.rmtree(os.path.join(directory, "build"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "htmlcov"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "deb_dist"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "doc", "code"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "doc", "_build"), ignore_errors=True)
    shutil.rmtree(
        os.path.join(directory, "SawtoothLakeLedger.egg-info"),
        ignore_errors=True)
