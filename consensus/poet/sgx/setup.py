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
from distutils.command import build_ext as build_ext_module
from shutil import copyfile

script_dir = os.path.dirname(os.path.realpath(__file__))

is_simulator_build = '--simulator' in sys.argv
if is_simulator_build:
    sys.argv.remove('--simulator')

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

    if is_simulator_build:
        ext_deps = ['deps/bin/libpoet-bridge-simulator.dll',
                    'deps/bin/libpoet-enclave-simulator.signed.dll']
        libraries = ['libpoet-bridge-simulator']
    else:
        ext_deps = ['deps/bin/libpoet-bridge.dll',
                    'deps/bin/libpoet-enclave.signed.dll']
        libraries = ['libpoet-bridge']

    ext_deps += ['deps/bin/msvcp110.dll',
                 'deps/bin/msvcr110.dll']
    for f in ext_deps:
        package_data.append(os.path.basename(f))
    extra_compile_args = ['/EHsc']
    libraries += ['json-c', 'cryptopp-static']
    include_dirs = ['deps/include']

else:
    platform_dir = 'linux'
    package_data = []

    if is_simulator_build:
        ext_deps = ['deps/bin/libpoet-bridge-simulator.so',
                    'deps/bin/libpoet-enclave-simulator.signed.so']
        libraries = ['poet-bridge-simulator']
    else:
        ext_deps = ['deps/bin/libpoet-bridge.so',
                    'deps/bin/libpoet-enclave.signed.so']
        libraries = ['poet-bridge']

    extra_compile_args = ['-std=c++11']
    libraries += ['json-c', 'crypto++']

    include_dirs = []

include_dirs += ['sawtooth_poet_sgx/poet_enclave_sgx',
                 'sawtooth_poet_sgx/poet_enclave_sgx/{}'.format(platform_dir),
                 'sawtooth_poet_sgx/libpoet_shared',
                 'sawtooth_poet_sgx/libpoet_shared/{}'.format(platform_dir)]
library_dirs = ['deps/lib']

swig_opts = ['-c++']

if is_simulator_build:
    enclave_module_name = '_poet_enclave_simulator'
    package_name = 'sawtooth-poet-simulator'
    swig_opts += ['-DSGX_USE_SIMULATOR']
else:
    enclave_module_name = '_poet_enclave'
    package_name = 'sawtooth-poet-sgx'

enclavemod = Extension(enclave_module_name,
                       ['sawtooth_poet_sgx/poet_enclave_sgx/poet_enclave.i',
                        'sawtooth_poet_sgx/poet_enclave_sgx/common.cpp',
                        'sawtooth_poet_sgx/poet_enclave_sgx/poet.cpp',
                        'sawtooth_poet_sgx/poet_enclave_sgx/wait_certificate.cpp',
                        'sawtooth_poet_sgx/poet_enclave_sgx/wait_timer.cpp',
                        'sawtooth_poet_sgx/poet_enclave_sgx/signup_data.cpp',
                        'sawtooth_poet_sgx/poet_enclave_sgx/signup_info.cpp',
                        'sawtooth_poet_sgx/poet_enclave_sgx/{}/platform_support.cpp'.format(
                            platform_dir),
                        'sawtooth_poet_sgx/libpoet_shared/{}/c11_support.cpp'.format(
                            platform_dir)
                        ],
                       swig_opts=swig_opts,
                       extra_compile_args=extra_compile_args,
                       include_dirs=include_dirs,
                       libraries=libraries,
                       library_dirs=library_dirs)


class Build(build_module.build):
    # user_options = [
    #     ('simulator', None, 'Build PoET enclave for SGX SDK simulator')
    # ]
    # def initialize_options(self):
    #     super().initialize_options()
    #     self.simulator = False

    def build_poet(self):
        print('Building PoET SGX module')
        if not os.path.exists("build"):
            os.mkdir("build")
        os.chdir("build")

        if os.name == 'nt':
            config_args = ["-G", "Visual Studio 11 2012 Win64"]
        else:
            config_args = ["-G", "Unix Makefiles"]

        # If asked to build SGX SDK simulator, add config option
        if is_simulator_build:
            config_args.extend(["-D", "SGX_USE_SIMULATOR:BOOL=ON"])

        if os.name == 'nt':
            build_args = ["--config", "Release"]
        else:
            build_args = []

        subprocess.call(["cmake"] + config_args + [".."])
        subprocess.call(["cmake", "--build", "."] + build_args)

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


setup(name=package_name,
      version=version('0.8.4'),
      description='Sawtooth Lake PoET SGX Enclave',
      author='Intel Corporation',
      url='http://www.intel.com',
      packages=find_packages(),
      install_requires=[
          'toml',
          'ecdsa',
          'sawtooth-ias-client',
          'sawtooth-poet-common'
          ],
      ext_modules=[enclavemod],
      py_modules=['sawtooth_poet_sgx.poet_enclave_sgx.poet_enclave'],
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
                     "_poet_enclave_simulator{}".format(
                         sysconfig.get_config_var('EXT_SUFFIX')),
                     "libpoet-bridge.so",
                     "libpoet-bridge-simulator.so",
                     "libpoet-enclave.signed.so",
                     "libpoet-enclave-simulator.signed.so",
                     os.path.join(
                         "sawtooth_poet_sgx",
                         "poet_enclave_sgx",
                         "poet_enclave.py"),
                     os.path.join(
                         "sawtooth_poet_sgx",
                         "poet_enclave_sgx",
                         "poet_enclave_simulator.py"),
                     os.path.join(
                         "sawtooth_poet_sgx",
                         "poet_enclave_sgx",
                         "poet_enclave_wrap.cpp"),
                     "nose2-junit.xml"]:
        if os.path.exists(os.path.join(directory, filename)):
            os.remove(os.path.join(directory, filename))
    shutil.rmtree(os.path.join(directory, "build"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "htmlcov"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "deb_dist"), ignore_errors=True)
