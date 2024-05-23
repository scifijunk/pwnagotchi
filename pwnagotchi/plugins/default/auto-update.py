import os
import re
import logging
import subprocess
import requests
import platform
import shutil
import glob
from threading import Lock
import time

import pwnagotchi
import pwnagotchi.plugins as plugins
from pwnagotchi.utils import StatusFile, parse_version as version_to_tuple


def check_remote_version(version, repo, native=True):
    logging.debug("Checking remote version for %s, local is %s" % (repo, version))
    info = {
        'repo': repo,
        'current': version,
        'available': None,
        'url': None,
        'native': native,
        'arch': platform.machine()
    }

    try:
        resp = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
        resp.raise_for_status()
        latest = resp.json()
        info['available'] = latest_ver = latest['tag_name'].replace('v', '')

        is_arm = info['arch'].startswith('arm')
        local = version_to_tuple(info['current'])
        remote = version_to_tuple(latest_ver)

        if remote > local:
            if not native:
                info['url'] = f"https://github.com/{repo}/archive/{latest['tag_name']}.zip"
            else:
                for asset in latest['assets']:
                    download_url = asset['browser_download_url']
                    if download_url.endswith('.zip') and (
                            info['arch'] in download_url or (is_arm and 'armhf' in download_url)):
                        info['url'] = download_url
                        break
    except Exception as e:
        logging.error(f"Error checking remote version for {repo}: {e}")

    return info


def make_path_for(name):
    path = os.path.join("/tmp/updates/", name)
    try:
        if os.path.exists(path):
            logging.debug("[update] Deleting %s" % path)
            shutil.rmtree(path, ignore_errors=True, onerror=None)
        os.makedirs(path)
    except Exception as e:
        logging.error(f"Error creating path for {name}: {e}")
    return path


def download_and_unzip(name, path, display, update):
    target = f"{name}_{update['available']}.zip"
    target_path = os.path.join(path, target)

    try:
        logging.info("[update] Downloading %s to %s ..." % (update['url'], target_path))
        display.update(force=True, new_data={'status': f'Downloading {name} {update["available"]} ...'})
        subprocess.run(['wget', '-q', update['url'], '-O', target_path], check=True)

        logging.info("[update] Extracting %s to %s ..." % (target_path, path))
        display.update(force=True, new_data={'status': f'Extracting {name} {update["available"]} ...'})
        subprocess.run(['unzip', target_path, '-d', path], check=True)

    except Exception as e:
        logging.error(f"Error downloading and unzipping {name} update: {e}")


def verify(name, path, source_path, display, update):
    display.update(force=True, new_data={'status': f'Verifying {name} {update["available"]} ...'})

    try:
        checksums = glob.glob(f"{path}/*.sha256")
        if len(checksums) == 0:
            if update['native']:
                logging.warning("[update] Native update without SHA256 checksum file")
                return False
        else:
            checksum = checksums[0]
            logging.info(f"[update] Verifying {checksum} for {source_path} ...")

            with open(checksum, 'rt') as fp:
                expected = fp.read().split('=')[1].strip().lower()

            real = subprocess.getoutput(f'sha256sum "{source_path}"').split(' ')[0].strip().lower()

            if real != expected:
                logging.warning(f"[update] Checksum mismatch for {source_path}: expected={expected} got={real}")
                return False

    except Exception as e:
        logging.error(f"Error verifying {name} update: {e}")
        return False

    return True


def install(display, update):
    name = update['repo'].split('/')[1]
    path = make_path_for(name)

    download_and_unzip(name, path, display, update)

    source_path = os.path.join(path, name)
    if not verify(name, path, source_path, display, update):
        return False

    try:
        logging.info("[update] Installing %s ..." % name)
        display.update(force=True, new_data={'status': f'Installing {name} {update["available"]} ...'})

        if update['native']:
            dest_path = subprocess.getoutput(f"which {name}")
            if dest_path == "":
                logging.warning(f"[update] Can't find path for {name}")
                return False

            logging.info(f"[update] Stopping {update['service']} ...")
            subprocess.run(["service", update['service'], "stop"], check=True)

            subprocess.run(["mv", source_path, dest_path], check=True)
            logging.info(f"[update] Restarting {update['service']} ...")
            subprocess.run(["service", update['service'], "start"], check=True)
        else:
            if not os.path.exists(source_path):
                source_path = f"{source_path}-{update['available']}"

            subprocess.run(["cd", source_path, "&&", "pip3", "install", "."], check=True, shell=True)

    except Exception as e:
        logging.error(f"Error installing {name} update: {e}")
        return False

    return True


def parse_version(cmd):
    try:
        out = subprocess.getoutput(cmd)
        for part in out.split(' '):
            part = part.replace('v', '').strip()
            if re.search(r'^\d+\.\d+\.\d+.*$', part):
                return part
    except Exception as e:
        logging.error(f"Error parsing version from '{cmd}': {e}")
    raise Exception(f'Could not parse version from "{cmd}": output=\n{out}')


def check_remote_version_with_retry(version, repo, native=True, max_retries=3):
    retries = 0
    while retries < max_retries:
        try:
            resp = requests.get(f"https://api.github.com/repos/{repo}/releases/latest")
            resp.raise_for_status()
            latest = resp.json()
            return check_remote_version(version, repo, native)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                wait_time = 2 ** retries
                print(f"Rate limit exceeded. Retrying after {wait_time} seconds...")
                time.sleep(wait_time)
                retries += 1
            else:
                print(f"Error checking remote version for {repo}: {e}")
                raise e
        except requests.exceptions.ConnectionError as ce:
            wait_time = 2 ** retries
            print(f"Connection error. Retrying after {wait_time} seconds...")
            time.sleep(wait_time)
            retries += 1
    raise Exception(f"Failed to check remote version for {repo} after {max_retries} retries.")


class AutoUpdate(plugins.Plugin):
    __author__ = 'evilsocket@gmail.com'
    __version__ = '1.1.1'
    __name__ = 'auto-update'
    __license__ = 'GPL3'
    __description__ = 'This plugin checks when updates are available and applies them when internet is available.'

    def __init__(self):
        self.ready = False
        self.status = StatusFile('/root/.auto-update')
        self.lock = Lock()

    def on_loaded(self):
        if 'interval' not in self.options or ('interval' in self.options and not self.options['interval']):
            logging.error("[update] main.plugins.auto-update.interval is not set")
            return
        self.ready = True
        logging.info("[update] Plugin loaded.")

    def on_internet_available(self, agent):
        if self.lock.locked():
            return

        with self.lock:
            logging.debug("[update] Internet connectivity is available (ready %s)" % self.ready)

            if not self.ready:
                return

            if self.status.newer_then_hours(self.options['interval']):
                logging.debug("[update] Last check happened less than %d hours ago" % self.options['interval'])
                return

            logging.info("[update] Checking for updates ...")

            display = agent.view()
            prev_status = display.get('status')

            try:
                display.update(force=True, new_data={'status': 'Checking for updates ...'})

                to_install = []
                to_check = [
                    ('bettercap/bettercap', parse_version('bettercap -version'), True, 'bettercap'),
                    ('evilsocket/pwngrid', parse_version('pwngrid -version'), True, 'pwngrid-peer'),
                    ('scifijunk/pwnagotchi', pwnagotchi.__version__, False, 'pwnagotchi')
                ]

                for repo, local_version, is_native, svc_name in to_check:
                    info = check_remote_version_with_retry(local_version, repo, is_native)
                    if info['url'] is not None:
                        logging.warning(
                            f"Update for {repo} available (local version is '{info['current']}'): {info['url']}")
                        info['service'] = svc_name
                        to_install.append(info)

                num_updates = len(to_install)
                num_installed = 0

                if num_updates > 0:
                    if self.options['install']:
                        for update in to_install:
                            plugins.on('updating')
                            if install(display, update):
                                num_installed += 1
                    else:
                        prev_status = f"{num_updates} new update{'s' if num_updates > 1 else ''} available!"

                logging.info("[update] Done")

                self.status.update()

                if num_installed > 0:
                    display.update(force=True, new_data={'status': 'Rebooting ...'})
                    pwnagotchi.reboot()

            except Exception as e:
                logging.error("[update] %s" % e)

            display.update(force=True, new_data={'status': prev_status if prev_status is not None else ''})
