def pre_pin():
    # Attach Intel Pin to the services.exe process
    # based on its process ID
    import os
    os.system("taskkill /im explorer.exe /F")

    import puppeteering.util
    return puppeteering.util.get_pid_by_name("taskhost.exe")

def post_pin():
    # After Pin has been attached to the services.exe process,
    # start ZeroAccess
    import subprocess, os
    za_path = os.path.join(os.path.dirname(__file__), "goz.exe")
    subprocess.Popen([za_path])

def get_pin_args():
    # No additional arguments required (e.g.,
    # ZeroAccess does not start new processes)
    return []

def get_tool_args():
    return []

def get_privilege_level():
    # Run Intel Pin as normal user
    return 0