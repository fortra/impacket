import win32file, win32pipe, pywintypes

PIPE = r"\\.\pipe\echo"
BUFSIZE = 512

class Iocp:
    def __init__(self, object):
        self.port = win32file.CreateIoCompletionPort(-1, 0, 0, 0)
        win32file.CreateIoCompletionPort(object.handle, self.port, 1, 0)

    def wait_buggy(self):
        win32file.GetQueuedCompletionStatus(self.port, -1)

    def wait_good(self):
        # keep a reference to the overlapped object
        self.result = win32file.GetQueuedCompletionStatus(self.port, -1)[3]

class PipeService:
    def __init__(self):
        self.handle = win32pipe.CreateNamedPipe(PIPE,
                          win32pipe.PIPE_ACCESS_DUPLEX|
                          win32file.FILE_FLAG_OVERLAPPED,
                          win32pipe.PIPE_TYPE_MESSAGE|
                          win32pipe.PIPE_READMODE_MESSAGE|
                          win32pipe.PIPE_WAIT,
                          1, BUFSIZE, BUFSIZE,
                          win32pipe.NMPWAIT_WAIT_FOREVER,
                          None)
        win32pipe.ConnectNamedPipe(self.handle, None)

    def serve(self):
        print "Got connection"
        win32file.WriteFile(self.handle, 'Hello!\n')
        while 1:
            data = win32file.ReadFile(self.handle, BUFSIZE)[1]
            print "Got data: %r" % data
            if not data[:4] == 'tran':
                win32file.WriteFile(self.handle, data)
            print "Sent data"
            if data[:4] == 'quit':
                break

    def __del__(self):
        win32pipe.DisconnectNamedPipe(self.handle)

if __name__ == '__main__':
    import sys
    if 's' in sys.argv:
        svc = PipeService()
        iocp = Iocp(svc)
        if 'bug' in sys.argv:
            iocp.wait_buggy()
        else:
            iocp.wait_good()
        svc.serve()
    elif 'c' in sys.argv:
        print win32pipe.CallNamedPipe(PIPE, "Hello there", BUFSIZE, 0)

        
