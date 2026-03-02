"""Transfer Android project to jagg via jump host and build APK."""
import paramiko
import os
import stat
import time

JUMP_HOST = os.environ.get('JUMP_HOST', '192.168.0.200')
TARGET_HOST = os.environ.get('TARGET_HOST', '192.168.0.224')
USERNAME = os.environ.get('SSH_USERNAME', 'om')
PASSWORD = os.environ.get('SSH_PASSWORD', '')
LOCAL_PROJECT = os.path.dirname(os.path.abspath(__file__))
REMOTE_DIR = '/home/om/automaite-android'


def get_jump_transport():
    """Connect to jump host."""
    print(f"[*] Connecting to jump host {JUMP_HOST}...")
    transport = paramiko.Transport((JUMP_HOST, 22))
    transport.connect(username=USERNAME, password=PASSWORD)
    print("[+] Connected to jump host")
    return transport


def get_target_client(jump_transport):
    """Connect to target through jump host."""
    print(f"[*] Tunneling to target {TARGET_HOST}...")
    channel = jump_transport.open_channel(
        'direct-tcpip',
        (TARGET_HOST, 22),
        ('127.0.0.1', 0)
    )
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        TARGET_HOST,
        username=USERNAME,
        password=PASSWORD,
        sock=channel,
        timeout=30
    )
    print("[+] Connected to target")
    return client


def upload_project(sftp):
    """Upload the Android project files recursively."""
    print(f"[*] Uploading project to {REMOTE_DIR}...")

    # Files and dirs to skip
    skip = {'.gradle', 'build', '.idea', 'deploy_and_build.py', '__pycache__', '.git'}

    def ensure_remote_dir(path):
        try:
            sftp.stat(path)
        except FileNotFoundError:
            sftp.mkdir(path)

    ensure_remote_dir(REMOTE_DIR)

    for root, dirs, files in os.walk(LOCAL_PROJECT):
        dirs[:] = [d for d in dirs if d not in skip]

        rel_root = os.path.relpath(root, LOCAL_PROJECT).replace('\\', '/')
        if rel_root == '.':
            remote_root = REMOTE_DIR
        else:
            remote_root = f"{REMOTE_DIR}/{rel_root}"

        ensure_remote_dir(remote_root)

        for fname in files:
            if fname in skip:
                continue
            local_path = os.path.join(root, fname)
            remote_path = f"{remote_root}/{fname}"
            print(f"  -> {remote_path}")
            sftp.put(local_path, remote_path)

    print("[+] Upload complete")


def run_cmd(client, cmd, timeout=300):
    """Execute command and stream output."""
    print(f"[*] Running: {cmd}")
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)

    out = stdout.read().decode()
    err = stderr.read().decode()
    exit_code = stdout.channel.recv_exit_status()

    if out:
        print(out)
    if err:
        print(f"[stderr] {err}")

    return exit_code, out, err


def main():
    jump_transport = get_jump_transport()
    client = get_target_client(jump_transport)
    sftp = client.open_sftp()

    try:
        # Clean previous build
        run_cmd(client, f"rm -rf {REMOTE_DIR}")

        # Upload project
        upload_project(sftp)

        # Fix line endings and make gradlew executable
        run_cmd(client, f"cd {REMOTE_DIR} && sed -i 's/\\r$//' gradlew && chmod +x gradlew")

        # Check environment and find Android SDK
        run_cmd(client, f"echo 'JAVA_HOME='$JAVA_HOME; java -version 2>&1; gradle --version 2>&1 | head -3")

        # Find ANDROID_HOME and create local.properties
        print("\n[*] Locating Android SDK...")
        code, out, err = run_cmd(client,
            "for d in $ANDROID_HOME $ANDROID_SDK_ROOT ~/Android/Sdk ~/android-sdk /opt/android-sdk /usr/lib/android-sdk; do "
            "  if [ -d \"$d\" ]; then echo \"FOUND:$d\"; break; fi; "
            "done; "
            "cat ~/.bashrc 2>/dev/null | grep -i android | head -5"
        )
        sdk_dir = None
        for line in out.splitlines():
            if line.startswith("FOUND:"):
                sdk_dir = line.split(":", 1)[1]
                break
        if not sdk_dir:
            # Parse from bashrc export
            for line in out.splitlines():
                if 'ANDROID_HOME' in line or 'ANDROID_SDK_ROOT' in line:
                    parts = line.split('=')
                    if len(parts) >= 2:
                        sdk_dir = parts[-1].strip().strip('"').strip("'")
                        break
        if sdk_dir:
            print(f"[+] Android SDK at: {sdk_dir}")
            # Write local.properties
            run_cmd(client, f"echo 'sdk.dir={sdk_dir}' > {REMOTE_DIR}/local.properties")
        else:
            print("[!] Could not find Android SDK, build may fail")

        # Generate Gradle wrapper using system Gradle
        print("\n[*] Generating Gradle wrapper...")
        code, out, err = run_cmd(client, f"""
            cd /tmp && rm -rf gradle-wrapper-gen && mkdir gradle-wrapper-gen && cd gradle-wrapper-gen && \
            touch settings.gradle && \
            gradle wrapper --gradle-version 8.5 2>&1 && \
            cp -f gradle/wrapper/gradle-wrapper.jar {REMOTE_DIR}/gradle/wrapper/gradle-wrapper.jar && \
            cp -f gradlew {REMOTE_DIR}/gradlew && \
            chmod +x {REMOTE_DIR}/gradlew && \
            echo 'Wrapper generated successfully'
        """, timeout=120)

        if code != 0:
            print(f"[!] Gradle wrapper generation failed (exit {code})")
            return False

        # Build APK
        print("\n[*] Building APK (this may take a while on first run)...")
        code, out, err = run_cmd(client,
            f"cd {REMOTE_DIR} && ./gradlew assembleDebug --no-daemon 2>&1",
            timeout=600
        )

        if code != 0:
            print(f"\n[!] Build failed with exit code {code}")
            return False

        # Check for APK
        code, out, err = run_cmd(client, f"ls -la {REMOTE_DIR}/app/build/outputs/apk/debug/*.apk 2>/dev/null")
        if code == 0 and 'apk' in out:
            print("\n[+] APK built successfully!")

            # Download APK
            apk_remote = f"{REMOTE_DIR}/app/build/outputs/apk/debug/app-debug.apk"
            apk_local = os.path.join(LOCAL_PROJECT, 'app-debug.apk')
            print(f"[*] Downloading APK to {apk_local}...")
            sftp.get(apk_remote, apk_local)
            print(f"[+] APK downloaded: {apk_local}")
            print(f"    Size: {os.path.getsize(apk_local)} bytes")
            return True
        else:
            print("\n[!] APK not found after build")
            return False

    finally:
        sftp.close()
        client.close()
        jump_transport.close()
        print("\n[*] Connections closed")


if __name__ == '__main__':
    main()
