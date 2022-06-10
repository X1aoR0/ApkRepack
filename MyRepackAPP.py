import lzma
import os
import shutil
import tempfile
import xml.etree.ElementTree as ElementTree
from pkg_resources import parse_version
import re

import click
import delegator
import requests
import sys
import click
import shlex
from subprocess import list2cmdline


def list2posix_cmdline(seq):
    """
        Translate a sequence of arguments into a command line
        string.

        Implemented using shlex.quote because
        subprocess.list2cmdline doesn't work with POSIX
    """

    return ' '.join(map(shlex.quote, seq))






class AndroidPatcher():
    """ Class used to patch Android APK's"""
    # required tools
    required_commands = {
        'aapt': {
            'installation': 'apt install aapt (Kali Linux)'
        },
        'adb': {
            'installation': 'apt install adb (Kali Linux); brew install adb (macOS)'
        },
        'jarsigner': {
            'installation': 'apt install default-jdk (Linux); brew cask install java (macOS)'
        },
        'apktool': {
            'installation': 'apt install apktool (Kali Linux)'
        },
        'zipalign': {
            'installation': 'apt install zipalign'
        }
    }

    def _check_commands(self) -> bool:
        """
            Check if the shell commands in required_commands are
            available.

            :return:
        """

        for cmd, attributes in self.required_commands.items():

            location = shutil.which(cmd)

            if location is None:
                click.secho('Unable to find {0}. Install it with: {1} before continuing.'.format(
                    cmd, attributes['installation']), fg='red', bold=True)

                return False

            self.required_commands[cmd]['location'] = location

        return True

    def are_requirements_met(self):
        """
            Checks if the command requirements have all been met.

            :return:
        """

        return self.have_all_commands

    def __init__(self, skip_cleanup: bool = False, skip_resources: bool = False):
        # super(AndroidPatcher, self).__init__()

        self.apk_source = None
        if not os.path.exists("apk_unpack"):
            os.mkdir("apk_unpack")
        #self.apk_temp_directory = tempfile.mkdtemp(suffix='.apktemp')
        self.apk_temp_directory = "apk_unpack"
        self.apk_temp_frida_patched = self.apk_temp_directory + '.objection.apk'
        self.apk_temp_frida_patched_aligned = self.apk_temp_directory + '.aligned.objection.apk'
        self.aapt = None
        # default don't skip packing resources
        self.skip_cleanup = skip_cleanup
        self.skip_resources = skip_resources
        # sign apk
        self.keystore = os.path.join(os.path.abspath(os.path.dirname(__file__)),'objection.jks')
        self.netsec_config = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../assets',
                                          'network_security_config.xml')

        # check dependencies
        self.have_all_commands = self._check_commands()
        self.command_run_timeout = 60 * 5

        if os.name == 'nt':
            self.list2cmdline = list2cmdline
        else:
            self.list2cmdline = list2posix_cmdline

    def is_apktool_ready(self) -> bool:
        """
            Check if apktool is ready for use.

            :return:bool
        """

        min_version = '2.4.1'  # the version of apktool we require

        o = delegator.run(self.list2cmdline([
            self.required_commands['apktool']['location'],
            '-version',
        ]), timeout=self.command_run_timeout).out.strip()

        # On windows we get this 'Press any key to continue' thing,
        # localized to the the current language. Assume that the version
        # string we want is always the first line.
        if len(o.split('\n')) > 1:
            o = o.split('\n')[0]

        if len(o) == 0:
            click.secho('Unable to determine apktool version. Is it installed')
            return False

        click.secho('Detected apktool version as: ' + o, dim=True)

        # ensure we have at least apktool MIN_VERSION
        if parse_version(o) < parse_version(min_version):
            click.secho('apktool version should be at least ' + min_version, fg='red', bold=True)
            click.secho('Please see the following URL for more information: '
                        'https://github.com/sensepost/objection/wiki/Apktool-Upgrades', fg='yellow')
            return False

        # run clean-frameworks-dir
        click.secho('Running apktool empty-framework-dir...', dim=True)
        o = delegator.run(self.list2cmdline([
            self.required_commands['apktool']['location'],
            'empty-framework-dir',
        ]), timeout=self.command_run_timeout).out.strip()

        if len(o) > 0:
            click.secho(o, fg='yellow', dim=True)

        return True

    def set_apk_source(self, source: str):
        """
            Set the source APK to work with.

            :param source:
            :return:
        """

        if not os.path.exists(source):
            raise Exception('Source {0} not found.'.format(source))

        self.apk_source = source

        return self

    def unpack_apk(self):
        """
            Unpack an APK with apktool.

            :return:
        """

        click.secho('Unpacking {0}'.format(self.apk_source), dim=True)

        o = delegator.run(self.list2cmdline([
            self.required_commands['apktool']['location'],
            'decode',
            '-f',
            '-r' if self.skip_resources else '',
            '-o',
            self.apk_temp_directory,
            self.apk_source
        ]), timeout=self.command_run_timeout)



    def get_patched_apk_path(self) -> str:
        """
            Returns the path of the patched, aligned APK.

            :return:
        """

        return self.apk_temp_frida_patched_aligned

    def get_temp_working_directory(self) -> str:
        """
            Returns the temporary working directory used by this patcher.

            :return:
        """

        return self.apk_temp_directory

    def _get_appt_output(self):
        """
            Get the output of `aapt dump badging`.

            :return:
        """

        if not self.aapt:
            o = delegator.run(self.list2cmdline([
                self.required_commands['aapt']['location'],
                'dump',
                'badging',
                self.apk_source
            ]), timeout=self.command_run_timeout)

            if len(o.err) > 0:
                click.secho('An error may have occurred while running aapt.', fg='red')
                click.secho(o.err, fg='red')

            self.aapt = o.out

        return self.aapt

    def _get_android_manifest(self) -> ElementTree:
        """
            Get the AndroidManifest as a parsed ElementTree

            :return:
        """

        # error if --skip-resources was used because the manifest is encoded
        if self.skip_resources is True:
            click.secho('Cannot manually parse the AndroidManifest.xml when --skip-resources '
                        'is set, remove this and try again.', fg='red')
            raise Exception('Cannot --skip-resources when trying to manually parse the AndroidManifest.xml')

        # use the android namespace
        ElementTree.register_namespace('android', 'http://schemas.android.com/apk/res/android')

        return ElementTree.parse(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'))

    def inject_internet_permission(self):
        """
            Checks the status of the source APK to see if it
            has the INTERNET permission. If not, the manifest file
            is parsed and the permission injected.

            :return:
        """

        internet_permission = 'android.permission.INTERNET'

        # if the app already has the internet permission, easy mode :D
        if internet_permission in self._get_appt_output():
            click.secho('App already has android.permission.INTERNET', fg='green')
            return

        # if not, we need to inject an element with it
        click.secho('App does not have android.permission.INTERNET, attempting to patch the AndroidManifest.xml...',
                    dim=True, fg='yellow')
        xml = self._get_android_manifest()
        root = xml.getroot()

        click.secho('Injecting permission: {0}'.format(internet_permission), fg='green')

        # prepare a new 'uses-permission' tag
        child = ElementTree.Element('uses-permission')
        child.set('android:name', internet_permission)
        root.append(child)

        click.secho('Writing new Android manifest...', dim=True)

        xml.write(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'),
                  encoding='utf-8', xml_declaration=True)

    def _get_launchable_activity(self) -> str:
        """
            Determines the class name for the activity that is
            launched on application startup.

            This is done by first trying to parse the output of
            aapt dump badging, then falling back to manually
            parsing the AndroidManifest for activity-alias tags.

            :return:
        """

        activities = (match.groups()[0] for match in
                      re.finditer(r"^launchable-activity: name='([^']+)'", self._get_appt_output(), re.MULTILINE))
        activity = next(activities, None)

        # If we got the activity using aapt, great, return that
        if activity is not None:
            return activity

        # if we dont have the activity yet, check out activity aliases
        click.secho(('Unable to determine the launchable activity using aapt, trying '
                     'to manually parse the AndroidManifest for activity aliases...'), dim=True, fg='yellow')

        # Try and parse the manifest manually
        manifest = self._get_android_manifest()
        root = manifest.getroot()

        # grab all of the activity-alias tags
        for alias in root.findall('./application/activity-alias'):

            # Take not of the current activity
            current_activity = alias.get('{http://schemas.android.com/apk/res/android}targetActivity')
            categories = alias.findall('./intent-filter/category')

            # make sure we have categories for this alias
            if categories is None:
                continue

            for category in categories:

                # check if the name of this category is that of LAUNCHER
                # its possible to have multiples, but once we determine one
                # that fits we can just return and move on
                category_name = category.get('{http://schemas.android.com/apk/res/android}name')

                if category_name == 'android.intent.category.LAUNCHER':
                    return current_activity

        # getting here means we were unable to determine what the launchable
        # activity is
        click.secho('Unable to determine the launchable activity for this app.', fg='red')
        raise Exception('Unable to determine launchable activity')

    def _determine_smali_path_for_class(self, target_class) -> str:
        """
            Attempts to determine the local path for a target class' smali

            :param target_class:
            :return:
        """

        # convert to a filesystem path, just like how it would be on disk
        # from the apktool dump
        target_class = target_class.replace('.', '/')

        activity_path = os.path.join(self.apk_temp_directory, 'smali', target_class) + '.smali'

        # check if the activity path exists. If not, try and see if this may have been
        # a multidex setup
        if not os.path.exists(activity_path):

            click.secho('Smali not found in smali directory. This might be a multidex APK. Searching...', dim=True)

            # apk tool will dump the dex classes to a smali directory. in multidex setups
            # we have folders such as smali_classes2, smali_classes3 etc. we will search
            # those paths for the launch activity we detected.
            for x in range(2, 100):
                smali_path = os.path.join(self.apk_temp_directory, 'smali_classes{0}'.format(x))

                # stop if the smali_classes directory does not exist.
                if not os.path.exists(smali_path):
                    break

                # determine the path to the launchable activity again
                activity_path = os.path.join(smali_path, target_class) + '.smali'

                # if we found the activity, stop the loop
                if os.path.exists(activity_path):
                    click.secho('Found smali at: {0}'.format(activity_path), dim=True)
                    break

        # one final check to ensure we have the target .smali file
        if not os.path.exists(activity_path):
            raise Exception('Unable to find smali to patch!')

        return activity_path

    # def __del__(self):
    #     """
    #         Cleanup after ourselves.

    #         :return:
    #     """

    #     if self.skip_cleanup:
    #         click.secho('Not cleaning up temporary files', dim=True)
    #         return

    #     click.secho('Cleaning up temp files...', dim=True)

    #     try:

    #         shutil.rmtree(self.apk_temp_directory, ignore_errors=True)
    #         os.remove(self.apk_temp_frida_patched)
    #         os.remove(self.apk_temp_frida_patched_aligned)

    #     except Exception as err:
    #         click.secho('Failed to cleanup with error: {0}'.format(err), fg='red', dim=True)

    def build_new_apk(self, use_aapt2: bool = False):
        """
            Build a new .apk with the frida-gadget patched in.

            :return:
        """

        click.secho('Rebuilding the APK with the frida-gadget loaded...', fg='green', dim=True)
        o = delegator.run(
            self.list2cmdline([self.required_commands['apktool']['location'],
                               'build',
                               self.apk_temp_directory,
                               ] + (['--use-aapt2'] if use_aapt2 else []) + [
                                  '-o',
                                  self.apk_temp_frida_patched
                              ]), timeout=self.command_run_timeout)



        click.secho('Built new APK with injected loadLibrary and frida-gadget', fg='green')

    def zipalign_apk(self):
        """
            Performs the zipalign command on an APK.

            :return:
        """

        click.secho('Performing zipalign', dim=True)

        o = delegator.run(self.list2cmdline([
            self.required_commands['zipalign']['location'],
            '-p',
            '4',
            self.apk_temp_frida_patched,
            self.apk_temp_frida_patched_aligned
        ]))



    def sign_apk(self):
        """
            Signs an APK with the objection key.

            The keystore itself was created with:
                keytool -genkey -v -keystore objection.jks -alias objection -keyalg RSA -keysize 2048 -validity 3650
                pass: basil-joule-bug

            :return:
        """

        click.secho('Signing new APK.', dim=True)

        o = delegator.run(self.list2cmdline([
            self.required_commands['jarsigner']['location'],
            '-sigalg',
            'SHA1withRSA',
            '-digestalg',
            'SHA1',
            '-tsa',
            'http://timestamp.digicert.com',
            '-storepass',
            'basil-joule-bug',
            '-keystore',
            self.keystore,
            self.apk_temp_frida_patched_aligned,
            'objection'
        ]))

        click.secho('Signed the new APK', fg='green')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("command sample: unpack x.apk")
        print("command sample: pack x.apk.dir")
        exit(0)
    apkrePacker = AndroidPatcher()
    # set target apk
    
    #print(sys.argv[0] + sys.argv[1] + sys.argv[2])
    if sys.argv[1] == "unpack":
        apkrePacker.set_apk_source(sys.argv[2])
        # use apktool to unpack target apk
        apkrePacker.unpack_apk()
    elif sys.argv[1] == "pack":
        apkrePacker.build_new_apk()
        apkrePacker.zipalign_apk()
        apkrePacker.sign_apk()
