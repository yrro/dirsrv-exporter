import ctypes


libpthread = ctypes.CDLL("libpthread.so.0")

pthread_setname_np = libpthread.pthread_setname_np
pthread_setname_np.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
pthread_setname_np.restype = ctypes.c_int


def set_name(thread, name):
    thread.name = name
    return libpthread.pthread_setname_np(thread.ident, name.encode())
