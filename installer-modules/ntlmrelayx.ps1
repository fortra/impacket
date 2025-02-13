function Main {
    return @('--exclude-module', 'tkinter', '--collect-all', 'impacket.examples.ntlmrelayx')
}

function Cleanup {}