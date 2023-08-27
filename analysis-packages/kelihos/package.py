def pre_pin():
    # Make Intel Pin attach to the kelihos.exe process
    # 2 seconds after starting it
    import subprocess, os, time, puppeteering.util
    za_path = os.path.join(os.path.dirname(__file__), "kelihos.exe")
    subprocess.Popen([za_path])

    time.sleep(2)

    return puppeteering.util.get_pid_by_name("kelihos.exe")

def post_pin():
    # After Intel Pin is started, no further action
    # is necessary
    pass

def get_pin_args():
    # return []
    # We need Intel Pin to also instrument newly
    # created processes
    return ["-follow_execv"]

def get_tool_args():
    return []

def get_privilege_level():
    # Run Intel Pin as normal user
    return 0