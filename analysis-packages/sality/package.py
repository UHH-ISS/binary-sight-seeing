def pre_pin():
    # Make Intel Pin instrument the sality.exe binary
    return "sality.exe"

def post_pin():
    # After Intel Pin is started, no further action
    # is necessary
    pass

def get_pin_args():
    # We need Intel Pin to also instrument newly
    # created processes
    return ["-follow_execv"]

def get_tool_args():
    return []

def get_privilege_level():
    # Run Intel Pin as normal user
    return 0