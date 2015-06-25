#!/usr/bin/python
# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Parallel Coordinates traffic grapher.
#
# This grapher uses the pcap library to listen for packets in transit
# over the specified interface. The returned packages can be filtered
# according to a BPF filter (see tcpdump(3) for further information on
# BPF filters). The packets are displayed on a parallel coordinates
# graph that allows the user to visualize the traffic flow on the
# network in real-time.
#
# The graphing part requires Tk support. Note that the user might need
# special permissions to be able to use pcap.
#
# Authors:
#  Gerardo Richarte <gera@coresecurity.com>
#  Javier Kohen <jkohen@coresecurity.com>
#
# Reference for:
#  pcapy: findalldevs, open_live.
#  ImpactPacket.
#  ImpactDecoder.

## Some tunable variables follow.

# Period (in ms.) to wait between pcap polls.
POLL_PERIOD = 250

# Period (in ms.) to wait between screen refreshes.
REFRESH_PERIOD = 1000

# Refresh screen after receiving new packets.
# You might want to turn off fast_draws if it consumes too much CPU,
# for instance, when used under X-Window over a network link.
fast_draws = 1

## End of user configurable section.


import socket
import sys
import time
import Tkinter
import pcapy
from pcapy import open_live, findalldevs, PcapError

from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder


class NumericAxis:
    def __init__(self,canvas,name,low=0,high=0,direction='vertical'):
        self.canvas = canvas
        self.name = name
        self.setLowerLimit(low)
        self.setHigherLimit(high)
        self.direction = direction

    def screenLength(self):
        if self.direction == 'vertical':
            return (self.canvas.winfo_height())-10
        else:
            return (self.canvas.winfo_width())-10

    def scaleLength(self):
        delta = self.getHigherLimit()-self.getLowerLimit()
        if not delta:
            delta += 1
        return delta

    def unscale(self,coord):
        return int((coord-5)*self.scaleLength()/self.screenLength()+self.getLowerLimit())

    def scale(self,value):
        return (value-self.getLowerLimit())*self.screenLength()/self.scaleLength()+5

    def setLowerLimit(self,limit):
        if not limit == None:
            self._lowerLimit = limit

    def setHigherLimit(self,limit):
        if not limit == None:
            self._higherLimit = limit

    def getLowerLimit(self):
        return self._lowerLimit

    def getHigherLimit(self):
        return self._higherLimit

    def addValue(self,value):
        if self.getLowerLimit() > value:
            self.setLowerLimit(value)
        if self.getHigherLimit() < value:
            self.setHigherLimit(value)

class SymbolicAxis(NumericAxis):
    def __init__(self,canvas,name,values=[],direction = 'vertical'):
        NumericAxis.__init__(self,canvas,name,0,len(values)-1,direction)
        self.values = list(values)

    def addValue(self,value,sort = 1):
        try:
            self.values.index(value)
            return
        except:
            None
        self.values.append(value)
        if sort:
            self.values.sort()
        self.setHigherLimit(len(self.getValues())-1)

    def unscale(self,value):
        try:
            i = NumericAxis.unscale(self, value)
            if i < 0: return None
            return self.getValues()[i]
        except Exception,e:
            return None

    def scale(self,value):
        try:
            return NumericAxis.scale(self,self.getValues().index(value))
        except:
            self.addValue(value)
        return NumericAxis.scale(self,self.values.index(value))

    def getValues(self):
        return self.values

class ParallelCoordinates(Tkinter.Canvas):
    def __init__(self, master=None, cnf={}, **kw):
        apply(Tkinter.Canvas.__init__, (self, master, cnf), kw)

        self.lastSelection = None
        self.lastSelectionOval = None
        self._onSelection = None

        self.minColor = None
        self.maxColor = None
        self.colorAxis = '_counter'

        self.values=[]
        self.mainAxis=SymbolicAxis(self,'mainAxis',[],'horizontal')

        master.bind('<Visibility>',self.draw)
        master.bind('<Motion>',self.buttonDown)
        master.bind('<1>',self.buttonDown)
        master.bind('<ButtonRelease-1>',self.buttonUp)

    def addAxis(self,axis):
        self.mainAxis.addValue(axis,0)

    def sameValue(self,a,b):
        for axis in self.mainAxis.getValues():
            if not a[axis.name] == b[axis.name]:
                return 0
        return 1

    def addValue(self,value):
        for each in self.values:
            if self.sameValue(value,each):
                each['_counter'] += 1
                each['timestamp'] = value['timestamp']
                value = each
                break
        else:
            value['_counter'] = 1
            for axis in self.mainAxis.getValues():
                axis.addValue(value[axis.name])
            self.values.append(value)

        color = value[self.colorAxis]
        if None == self.minColor or self.minColor > color:
            self.minColor = color

        if None == self.maxColor or self.maxColor < color:
            self.maxColor = color

    def removeValue(self, value):
        self.values.remove(value)

    def basicColor(self,val,fade = 1):
        # color scale is linear going through green -> yellow -> red
        # (lower to higher)

        if val < 0.5:
            val += val     # val *= 2 (scale from 0 to 1)
            # between green - yellow
            red   = 64*(1-val)  + 255*val
            green = 200*(1-val) + 255*val
            blue  = 64*(1-val)  + 0
        else:
            val -= 0.5
            val += val
            red   = 255*(1-val) + 255*val
            green = 255*(1-val) + 64*val
            blue  = 0           + 0

        return '#%02x%02x%02x' % (int(red*fade), int(green*fade), int(blue*fade))

    def fade(self,value):
        return max(0,(120.0-time.time()+value['timestamp'])/120.0)

    def color(self,value,fade = 1):
        # color scale is linear going through green -> yellow -> red (lower to higher)
        val = float(value[self.colorAxis]-self.minColor)/(self.maxColor-self.minColor+1)
        return self.basicColor(val,fade)

    def drawValueLine(self,value):
        x = -1
        y = -1
        fade = self.fade(value)
        if not fade:
            self.removeValue(value)
            return

        color = self.color(value,fade)

        for axis in self.mainAxis.getValues():
            px = x
            py = y
            x = self.mainAxis.scale(axis)
            y = axis.scale(value[axis.name])
            if not px == -1:
                self.create_line(px,py,x,y,fill = color)

    def draw(self,event = None):
        # draw axis
        for i in self.find_all():
            self.delete(i)

        for axis in self.mainAxis.getValues():
            x = self.mainAxis.scale(axis)
            self.create_line(x,5,x,int(self.winfo_height())-5,fill = 'white')

        for value in self.values:
            self.drawValueLine(value)

#       draw color range
#        for i in range(200):
#            c = self.basicColor((i+0.0)/200)
#            self.create_line(0,i,100,i,fill = c)

    def buttonDown(self,event):
        if (event.state & 0x0100) or (event.type == '4'):
            axis = self.mainAxis.unscale(event.x)
            if not axis: return
            element = axis.unscale(event.y)
            if not element: return

            x = self.mainAxis.scale(axis)
            y = axis.scale(element)

            if self.lastSelectionOval:
                self.delete(self.lastSelectionOval)
            self.lastSelectionOval = self.create_oval(x-3,y-3,x+3,y+3,fill = "yellow")

            if not self.lastSelection == (axis,element):
                self.lastSelection = (axis,element)
                if self._onSelection:
                    self._onSelection(self.lastSelection)


    def buttonUp(self,event):
        if self.lastSelectionOval:
            self.delete(self.lastSelectionOval)
            self.lastSelectionOval = None
            self.lastSelection = None
            if self._onSelection:
                self._onSelection(None)

    def onSelection(self,_onSelection):
        self._onSelection = _onSelection


class Tracer:
    def __init__(self, interface = 'eth0', filter = ''):
        print "Tracing interface %s with filter `%s'." % (interface, filter)

        self.tk = Tkinter.Tk()
        self.pc = ParallelCoordinates(self.tk,background = "black")
        self.pc.pack(expand=1, fill="both")
        self.status = Tkinter.Label(self.tk)
        self.status.pack()
        self.tk.tkraise()
        self.tk.title('Personal SIDRA (IP-Tracer)')

        self.pc.addAxis(NumericAxis(self.pc, 'proto',256))
        self.pc.addAxis(SymbolicAxis(self.pc,'shost'))
        self.pc.addAxis(SymbolicAxis(self.pc,'sport'))
        self.pc.addAxis(SymbolicAxis(self.pc,'dport'))
        self.pc.addAxis(SymbolicAxis(self.pc,'dhost'))
        self.pc.onSelection(self.newSelection)

        self.interface = interface
        self.filter = filter

    def timerDraw(self,event = None):
        self.pc.draw()
        self.tk.after(REFRESH_PERIOD, self.timerDraw);

    def start(self):
        self.p = open_live(self.interface, 1600, 0, 100)
##         self.p.setnonblock(1)
        if self.filter:
            self.p.setfilter(self.filter)

        # Query the type of the link and instantiate a decoder accordingly.
        datalink = self.p.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)

        self.tk.after(POLL_PERIOD, self.poll)
        self.tk.after(REFRESH_PERIOD, self.timerDraw);
        self.tk.bind('q',self.quit)
        self.tk.mainloop()

    def quit(self,event):
        self.tk.quit()

    def poll(self,event = None):
        self.tk.after(POLL_PERIOD, self.poll)
        received = 0
        while 1:
            try:
                hdr, data = self.p.next()
            except PcapError, e:
                break
            self.newPacket(hdr.getcaplen(), data, hdr.getts()[0])
            received = 1
        if received and fast_draws:
            self.pc.draw()

    def newPacket(self, len, data, timestamp):
        try:
            p = self.decoder.decode(data)
        except Exception, e:
            pass
        value = {}
        try:
	    value['timestamp']=timestamp
            value['shost']=p.child().get_ip_src()
            value['dhost']=p.child().get_ip_dst()
            value['proto']=p.child().child().protocol
            value['sport']=-1
            value['dport']=-1
        except:
            return

        try:
            if value['proto'] == socket.IPPROTO_TCP:
                value['dport']=p.child().child().get_th_dport()
                value['sport']=p.child().child().get_th_sport()
            elif value['proto'] == socket.IPPROTO_UDP:
                value['dport']=p.child().child().get_uh_dport()
                value['sport']=p.child().child().get_uh_sport()
        except:
            pass

        self.pc.addValue(value)

    def setStatus(self,status):
        self.status.configure(text = status)

    def newSelection(self, selection):
        if selection:
            self.setStatus('%s:%s' % (selection[0].name, selection[1]))
        else:
            self.setStatus('')

def getInterfaces():
    # Grab a list of interfaces that pcap is able to listen on.
    # The current user will be able to listen from all returned interfaces,
    # using open_live to open them.
    ifs = findalldevs()

    # No interfaces available, abort.
    if 0 == len(ifs):
        return "You don't have enough permissions to open any interface on this system."

    return ifs

def printUsage():
        print """Usage: %s [interface [filter]]
Interface is the name of a local network interface, see the list of available interfaces below.
Filter is a BPF filter, as described in tcpdump(3)'s man page.

Available interfaces for this user: %s
""" % (sys.argv[0], getInterfaces())

def main():
    if len(sys.argv) == 1:
        printUsage()
        graph = Tracer()
    elif len(sys.argv) == 2:
        graph = Tracer(sys.argv[1])
    elif len(sys.argv) == 3:
        graph = Tracer(sys.argv[1],sys.argv[2])
    else:
        printUsage()
        sys.exit(1)
    graph.start()

main()

