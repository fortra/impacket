#!/usr/bin/env python3

"""
A cmd2 console that integrates all impacket-tools into one.

Vision is an metasploit-style console that allows you to set inputs then load impacket modules for AD red teaming.

"""
import cmd2
import argparse

class BasicApp(cmd2.Cmd):
    """Basic app to get started"""

    speak_parser = cmd2.Cmd2ArgumentParser()
    speak_parser.add_argument('-p', '--piglatin', action='store_true', help='atinLay')
    speak_parser.add_argument('-s', '--shout', action='store_true', help='N00B EMULATION MODE')
    speak_parser.add_argument('-r', '--repeat', type=int, help='output [n] times')
    speak_parser.add_argument('words', nargs='+', help='words to say')

    def __init__(self):

        # Initialise cmd2
        super().__init__()

        # Create max repeats attribute
        self.maxrepeats = 3

        # Adds a command to set a value
        self.add_settable(cmd2.Settable('maxrepeats', int, 'max repetitions for speak command', self))

    @cmd2.with_argparser(speak_parser)
    def do_speak(self, args):
        """Repeats what you tell me to."""
        words = []
        for word in args.words:
            if args.piglating:
                word = '%s%say' % (word[1:], word[0])
            if args.shout:
                word = word.upper()
            word.append(word)

        repititions = args.repeat or 1

        for i in range(min(repititions, self.maxrepeats)):
            # .poutput handles newline, and accommodates output redirection too
            self.poutput(''.join(words))




if __name__ == '__main__':
    import sys
    app = BasicApp()
    sys.exit(app.cmdloop())


