# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created: Mon Dec 28 19:52:30 2015
#      by: PyQt4 UI code generator 4.10.4
#
# WARNING! All changes made in this file will be lost!
import sys
import pcap
import string
import time
import socket
import struct
import os
import shutil
from PyQt4 import QtCore, QtGui

global filterRule
#utf-8
try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

try:
    _encoding = QtGui.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtGui.QApplication.translate(context, text, disambig)

#from sniff.py
protocols={socket.IPPROTO_TCP:'tcp',
            socket.IPPROTO_UDP:'udp',
            socket.IPPROTO_ICMP:'icmp',
            socket.IPPROTO_ICMPV6:'icmpv6',
            socket.IPPROTO_IGMP:'igmp',
            socket.IPPROTO_IPV6:'ipv6'}

#main window
class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName(_fromUtf8("MainWindow"))
        MainWindow.resize(800, 629)
        MainWindow.setMouseTracking(False)
        MainWindow.setContextMenuPolicy(QtCore.Qt.ActionsContextMenu)
	
#thread for capture~
	self.timeStamp=str(int(time.time()))
	self.thread=captureThread()
	self.sear_thread=searchThread()

	self.thread.changePath(self.timeStamp)
	self.sear_thread.changePath(self.timeStamp)

	self.selected_device=''
	self.search_Content=''
	self.fileSavePath='/home/py_sniff'
#for filter	
	self.selectedPacket=''
	self.filterDialog=Ui_Dialog()

        self.centralwidget = QtGui.QWidget(MainWindow)
        self.centralwidget.setObjectName(_fromUtf8("centralwidget"))

        self.horizontalLayoutWidget = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(20, 60, 383, 81))
        self.horizontalLayoutWidget.setObjectName(_fromUtf8("horizontalLayoutWidget"))

        self.horizontalLayout_2 = QtGui.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout_2.setMargin(0)
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))

        self.interface_2 = QtGui.QLabel(self.horizontalLayoutWidget)
        self.interface_2.setObjectName(_fromUtf8("interface_2"))
        self.horizontalLayout_2.addWidget(self.interface_2)
#show all avaliable devices
        self.select_interface = showAvaliableDev(self.horizontalLayoutWidget)
        self.select_interface.setObjectName(_fromUtf8("select_interface"))
        self.horizontalLayout_2.addWidget(self.select_interface)
	
#determine selected interface
        self.sure_interface = interfaceButton(self.horizontalLayoutWidget)
        self.sure_interface.setObjectName(_fromUtf8("sure_interface"))
        self.horizontalLayout_2.addWidget(self.sure_interface)
	

        spacerItem = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        self.horizontalLayout_2.addItem(spacerItem)
        self.horizontalLayoutWidget_2 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_2.setGeometry(QtCore.QRect(410, 60, 321, 81))
        self.horizontalLayoutWidget_2.setObjectName(_fromUtf8("horizontalLayoutWidget_2"))

        self.horizontalLayout_3 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_2)
        self.horizontalLayout_3.setMargin(0)
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))

        self.search = QtGui.QLabel(self.horizontalLayoutWidget_2)
        self.search.setObjectName(_fromUtf8("search"))
        self.horizontalLayout_3.addWidget(self.search)
        self.search_content = searchLineText(self.horizontalLayoutWidget_2)

        self.search_content.setObjectName(_fromUtf8("search_content"))
        self.horizontalLayout_3.addWidget(self.search_content)
        self.search_Button = searchButton(self.horizontalLayoutWidget_2)

        self.search_Button.setObjectName(_fromUtf8("searchButton"))
        self.horizontalLayout_3.addWidget(self.search_Button)


        spacerItem1 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)

        self.horizontalLayout_3.addItem(spacerItem1)
        self.horizontalLayoutWidget_3 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_3.setGeometry(QtCore.QRect(160, 150, 571, 271))
        self.horizontalLayoutWidget_3.setObjectName(_fromUtf8("horizontalLayoutWidget_3"))

        self.horizontalLayout_5 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_3)
        self.horizontalLayout_5.setMargin(0)
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
 
        self.pcap_table = showPacketList(self.horizontalLayoutWidget_3)
        self.pcap_table.setObjectName(_fromUtf8("pcap_table"))
        self.horizontalLayout_5.addWidget(self.pcap_table)
	self.pcap_table.connect(self.thread,QtCore.SIGNAL('CAPTURE_ONE_PACKET'),self.pcap_table.addItem)
#items_name
	

        self.pcap_tree = pktInfoView(self.centralwidget)
        self.pcap_tree.setGeometry(QtCore.QRect(20, 150, 131, 421))
        self.pcap_tree.setObjectName(_fromUtf8("pcap_tree"))
	self.pcap_tree.changePath(self.timeStamp)
	

        self.horizontalLayoutWidget_4 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_4.setGeometry(QtCore.QRect(160, 430, 571, 141))
        self.horizontalLayoutWidget_4.setObjectName(_fromUtf8("horizontalLayoutWidget_4"))

        self.horizontalLayout_6 = QtGui.QHBoxLayout(self.horizontalLayoutWidget_4)
        self.horizontalLayout_6.setMargin(0)
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))

        self.pcap_data = showData(self.horizontalLayoutWidget_4)
        self.pcap_data.setObjectName(_fromUtf8("pcap_data"))
	self.pcap_data.changePath(self.timeStamp)
        self.horizontalLayout_6.addWidget(self.pcap_data)
	#
	self.pcap_tree.connect(self.pcap_table,QtCore.SIGNAL('SELECTED_ONE_PACKET'),self.pcap_tree.showPacketInformation)
	self.pcap_tree.connect(self.pcap_table,QtCore.SIGNAL('SELECTED_ONE_PACKET'),self.pcap_data.showPacketData)
	self.pcap_tree.connect(self.pcap_table,QtCore.SIGNAL('SELECTED_ONE_PACKET'),self.changeSelectedPacket)
        self.horizontalLayoutWidget_5 = QtGui.QWidget(self.centralwidget)
        self.horizontalLayoutWidget_5.setGeometry(QtCore.QRect(20, 20, 713, 31))
        self.horizontalLayoutWidget_5.setObjectName(_fromUtf8("horizontalLayoutWidget_5"))

        self.horizontalLayout = QtGui.QHBoxLayout(self.horizontalLayoutWidget_5)
        self.horizontalLayout.setMargin(0)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))

        '''self.open_pcap = QtGui.QPushButton(self.horizontalLayoutWidget_5)
        self.open_pcap.setObjectName(_fromUtf8("open_pcap"))
        self.horizontalLayout.addWidget(self.open_pcap)'''

        self.save_pcap = QtGui.QPushButton(self.horizontalLayoutWidget_5)
        self.save_pcap.setObjectName(_fromUtf8("save_pcap"))
        self.horizontalLayout.addWidget(self.save_pcap)
#captureButton
        self.capture = captureButton(self.horizontalLayoutWidget_5)
        self.capture.setObjectName(_fromUtf8("capture"))
        self.horizontalLayout.addWidget(self.capture)

#some information should be given..seen in L62,L67
	QtCore.QObject.connect(self.capture,QtCore.SIGNAL('clickedMetoo'),self.thread.startCapture)
	QtCore.QObject.connect(self.sure_interface,QtCore.SIGNAL('clickMe'),self.captureGetDev)

        self.pause = QtGui.QPushButton(self.horizontalLayoutWidget_5)
        self.pause.setObjectName(_fromUtf8("pause"))
        self.horizontalLayout.addWidget(self.pause)
#try to stop capture
	QtCore.QObject.connect(self.pause,QtCore.SIGNAL('clicked()'),self.thread.terminate)

        self.filter = QtGui.QPushButton(self.horizontalLayoutWidget_5)
        self.filter.setObjectName(_fromUtf8("filter"))
        self.horizontalLayout.addWidget(self.filter)

        self.label_4 = QtGui.QLabel(self.horizontalLayoutWidget_5)
        self.label_4.setObjectName(_fromUtf8("label_4"))
        self.horizontalLayout.addWidget(self.label_4)

        spacerItem2 = QtGui.QSpacerItem(40, 20, QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem2)

        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtGui.QStatusBar(MainWindow)
        self.statusbar.setObjectName(_fromUtf8("statusbar"))
        MainWindow.setStatusBar(self.statusbar)

        self.actionInterface = QtGui.QAction(MainWindow)
        self.actionInterface.setObjectName(_fromUtf8("actionInterface"))

        self.actionSelect = QtGui.QAction(MainWindow)
        self.actionSelect.setObjectName(_fromUtf8("actionSelect"))

        self.interface_2.setBuddy(self.select_interface)
        self.search.setBuddy(self.search_content)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        MainWindow.setTabOrder(self.select_interface, self.pcap_tree)
        MainWindow.setTabOrder(self.pcap_tree, self.search_content)
        MainWindow.setTabOrder(self.search_content, self.search_Button)
	#select
	QtCore.QObject.connect(self.search_Button,QtCore.SIGNAL('clickMeThree'),self.search_content.getContent)
    	QtCore.QObject.connect(self.search_content,QtCore.SIGNAL('LETS_SEARCH'),self.sear_thread.searchPacket)	
    	QtCore.QObject.connect(self.sear_thread,QtCore.SIGNAL('FIND_STRING_IN_PACKET'),self.pcap_table.showSelectedPacket)
	#filter trigger
	QtCore.QObject.connect(self.filter,QtCore.SIGNAL('clicked()'),self.setFilter)
	#self.emit(QtCore.SIGNAL('GET_RULE'),filterRule)
	QtCore.QObject.connect(self.filterDialog,QtCore.SIGNAL('RULE_GET'),self.thread.changeRule)
	
	QtCore.QObject.connect(self.save_pcap, QtCore.SIGNAL('clicked()'), self.savePacket)
	
    def changeSelectedPacket(self,pkt_number):
	self.selectedPacket=pkt_number+1
	print self.selectedPacket
    def savePacket(self):
	src_path='/home/py_sniff/'+self.timeStamp+'/'+str(self.selectedPacket)+'.txt'
	des_path='/home/sniff_save/'+str(self.selectedPacket)+'.txt'
	print des_path
	if os.path.exists(des_path)==False:
		os.mknod(des_path)
	shutil.copy(src_path,des_path)
	print 'successfully saved'+str(self.selectedPacket)+'/'+str(self.selectedPacket)+'.txt'
#filter_window
    def setFilter(self):	
	self.filterDialog.exec_()
    

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle("~Sniffer_ZT>0<~")
        self.interface_2.setText(_translate("MainWindow", "Interface:", None))
        self.sure_interface.setText(_translate("MainWindow", "OK!", None))
        self.search.setText(_translate("MainWindow", "Search:", None))
        self.search_Button.setText(_translate("MainWindow", "Search it!", None))
        #self.open_pcap.setText(_translate("MainWindow", "Open pcap", None))
        self.save_pcap.setText(_translate("MainWindow", "Save pcap", None))
        self.capture.setText(_translate("MainWindow", "Capture", None))
        self.pause.setText(_translate("MainWindow", "Pause", None))
        self.filter.setText(_translate("MainWindow", "Filter", None))
        self.label_4.setText(_translate("MainWindow", "This sniffer was made by LZT @ F1303601 5130369007", None))
        self.actionInterface.setText(_translate("MainWindow", "Interface", None))
        self.actionSelect.setText(_translate("MainWindow", "Select", None))
	
    def captureGetDev(self,a):
	if a==1:
		self.selected_device=''
		self.selected_device=self.selected_device+self.select_interface.currentText()
		print self.selected_device+'~~~'
		self.capture.dev=self.selected_device
    
'''class fileSaving(QtGui.QfileDialog)
	def __init__(self,parent=None):
		QtGui.QfileDialog.__init__(self,Qwidget parent=None,Qstring caption=Qstring(),Qstring directory =Qstring(),Qstring filter=Qstring())
	def openFile(self):
		fileName = QFileDialog.getOpenFileName(self,self.tr(“Open Image”),Qstring(),self.tr(“Image Files(*.png *.jpg *.bmp)”))'''
#thread for search		
class searchThread(QtCore.QThread):
	def __init__(self,parent=None):
		QtCore.QThread.__init__(self,parent)
		self.exiting=False
		self.documentPath=''
		self.findString=''
	def changePath(self,path):
		self.documentPath=path

	def __del__(self):
		self.exiting=True
		self.wait()	
	def searchPacket(self,find_string):
		#print find_string
		self.findString=find_string
		self.start()
		
    	def run(self):
		i=1
		flag=0
		while os.path.exists(r'/home/py_sniff/'+self.documentPath+'/'+str(i)+'.txt')==True and not self.exiting:
			print 'openfile'+str(i)
			#print self.findString
			file_object=open(r'/home/py_sniff/'+self.documentPath+'/'+str(i)+'.txt','rb')
			all_text=file_object.read()
			#print all_text
			#print	'all_text.find(self.findString)=',str(all_text.find(self.findString))
			if(all_text.find(self.findString)!=-1):
				self.emit(QtCore.SIGNAL('FIND_STRING_IN_PACKET'),i)
			file_object.close()
			i=i+1
		print 'search over'
	
		
#search_linetext
class searchLineText(QtGui.QLineEdit):
	def __init__(self,parent=None):
		QtGui.QLineEdit.__init__(self,parent)
		self.text=''
	def getContent(self,a):
		if a==1:
			print 'getContent!'
			self.text=self.displayText()
			print self.text
			self.emit(QtCore.SIGNAL('LETS_SEARCH'),self.text)
#search_Button
class searchButton(QtGui.QPushButton):
	def __init__(self,parent=None):
		QtGui.QPushButton.__init__(self,parent)
	def mousePressEvent(self,event):
		print 'click search!'
		self.emit(QtCore.SIGNAL('clickMeThree'),1)
		
#tree_view of pkt info
class pktInfoView(QtGui.QTreeWidget):
	def __init__(self,parent=None):
		QtGui.QTreeWidget.__init__(self,parent)
		self.documentPath=''
		self.setHeaderLabel('pkt_info')

	def showPacketInformation(self,pkt_num):
		self.clear()
		#open the txt of packet
		print pkt_num
		infor=''
		child=[]
		file_object = open(r'/home/py_sniff/'+self.documentPath+'/'+str(pkt_num+1)+'.txt','rb')
		infor=file_object.readline()
		if infor[0:4]!='data' and infor!='':
			root=QtGui.QTreeWidgetItem(self)
			root.setText(0,infor)
			infor=file_object.readline()		
			i=0			
			while infor[0:4]!='data'and infor!='':
				print '['+infor+']'
				child.append(QtGui.QTreeWidgetItem(root))
				child[i].setText(0,str(infor))
				i=i+1
				infor=file_object.readline()
		print 'file closed'
		file_object.close()	

	def changePath(self,path):
		self.documentPath=path

#pressButton for interface list
class interfaceButton(QtGui.QPushButton):
	def __init__(self,parent=None):
		QtGui.QPushButton.__init__(self,parent)
	def mousePressEvent(self,event):
		self.emit(QtCore.SIGNAL('clickMe'),1)
		#print "clicked interface button"
		#makesure.changed the device
#pressButton for capture
class captureButton(QtGui.QPushButton):
	def __init__(self,parent=None):
		QtGui.QPushButton.__init__(self,parent)
		self.dev=''
	def mousePressEvent(self,event):
		#print 'click:dev:',self.dev
		self.emit(QtCore.SIGNAL('clickedMetoo'),self.dev)
	
#comboBox
class showAvaliableDev(QtGui.QComboBox):
	
	def __init__(self,parent=None):
		QtGui.QComboBox.__init__(self,parent)
		for name,descr, addrs, flags  in pcap.findalldevs():
        			self.addItem(name)
	def refresh(self,a):
		if a==1:
			self.clear()
			#get the information of all devices
    			for name,descr, addrs, flags  in pcap.findalldevs():
        			self.addItem(name)
			pcap.close()

		
class showData(QtGui.QTextBrowser):
	def __init(self,parent=None):
		QtGui.QTextBrowser.__init__(self,parent)
		self.documentPath=''
	def showPacketData(self,pkt_num):
		self.clear()
		#open the txt of packet
		print pkt_num
		file_object = open(r'/home/py_sniff/'+self.documentPath+'/'+str(pkt_num+1)+'.txt','rb')
		infor=file_object.readline()
		print '['+infor+']'
		while infor[0:4]!='data' and infor!='':
			infor=file_object.readline()
			#print '[['+infor+']]'
		while infor!=''and infor!='protocol:ARP':
			#print '~'+infor+'~'
			self.insertPlainText(infor)
			infor=file_object.readline()
		file_object.close()

	def changePath(self,path):
		self.documentPath=path		
#tableWidgit
class showPacketList(QtGui.QTableWidget):
	def __init__(self,parent=None):
		QtGui.QTableWidget.__init__(self,10000,7,parent)
		#self.setColumnCount(7)	
		self.setHorizontalHeaderLabels(['No.','Time','Source','Destination','Protocol','Lenth','Information'])
		#select row
		self.setSelectionBehavior(self.SelectRows)
		self.setSelectionMode(self.MultiSelection)	
	def showSelectedPacket(self,pkt_number):
		
		print pkt_number
		#i=0
		self.selectRow=pkt_number-1
		print '@'+str(self.selectRow)
		newItem = QtGui.QTableWidgetItem('@'+str(pkt_number))
                self.setItem(pkt_number-1,0,newItem)
		#self.setStyleSheet("selection-background-color:rgb(255,0,0)")
			#print 'paint!'
			#self.Item(pkt_number-1,i).setStyleSheet('{background-color:rgb(255,0,0)}')#red
			#i=i+1
	
	def addItem(self,num,stamp,source,destination,protocol,length,information):
		print num
		print stamp
		print source
		print destination
		print protocol
		print length
		print information
                newItem = QtGui.QTableWidgetItem(str(num))
                self.setItem(num-1,0,newItem)

		newItem = QtGui.QTableWidgetItem(stamp)
                self.setItem(num-1,1,newItem)

		newItem = QtGui.QTableWidgetItem(source)
                self.setItem(num-1,2,newItem)

		newItem = QtGui.QTableWidgetItem(destination)
                self.setItem(num-1,3,newItem)

		newItem = QtGui.QTableWidgetItem(protocol)
                self.setItem(num-1,4,newItem)

		newItem = QtGui.QTableWidgetItem(length)
                self.setItem(num-1,5,newItem)

		newItem = QtGui.QTableWidgetItem(information)
                self.setItem(num-1,6,newItem)
	def mousePressEvent(self,event):
		#show info left in tree widget && data below in txtbrowse
		#signal,treewidget,txtbrowse
		self.emit(QtCore.SIGNAL('SELECTED_ONE_PACKET'),self.currentRow())
		print self.currentRow()
		
#thread:capture
class captureThread(QtCore.QThread):
	def __init__(self,parent=None):
		QtCore.QThread.__init__(self,parent)
		self.exiting=False
		self.devi=''
		self.documentPath=''
		self.filter_rule=''
	def changeRule(self,rule):
		print 'rule changed!'
		self.filter_rule=rule
	def changePath(self,path):
		self.documentPath=path
	def __del__(self):
		self.exiting=True
		self.wait()

	def startCapture(self,dev):
				#dev should be got from interface....
				#so self.dev might be written here
				#self.ruleString L62
				#self.documentPath L67
		#self...=...
		#start a new thread for capturing
		print 'dev:',dev
		self.devi=dev
		self.start()
	def decode_ip_packet(self,s):
    		d={}
    		d['version']=(ord(s[0]) & 0xf0) >> 4 #s[0],s[1] is an ascii character
    		d['header_len']=ord(s[0]) & 0x0f   
    		d['tos']=ord(s[1])    #type of service
    		d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])  #ntohs()--"Network to Host Short"
    		d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0]) #fragment-reconstruction
    		d['flags']=(ord(s[6]) & 0xe0) >> 5    
    		d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    		d['ttl']=ord(s[8])
    		d['protocol']=ord(s[9])
    		d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    		d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    		d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
		if protocols[d['protocol']]=='tcp':
			d['source_port']=socket.ntohs(struct.unpack('H',s[20:22])[0]) 
			d['destination_port']=socket.ntohs(struct.unpack('H',s[22:24])[0]) 
			d['send_order']=str(struct.unpack('I',s[24:28])[0])
			d['def_order']=str(struct.unpack('I',s[28:32])[0])
			d['data_offset']=(ord(s[32]) & 0xf0) >> 4
			#s[33]:|_____|_____|_____|_____|_____|_____|_____|_____|
			#
			#      |_____|_____|_urg_|_ack_|_psh_|_rst_|_syn_|_fin_|    
 			d['urg']=(ord(s[33]) & 0x20) >> 5
			d['ack']=(ord(s[33]) & 0x10) >> 4
			d['psh']=(ord(s[33]) & 0x08) >> 3
			d['rst']=(ord(s[33]) & 0x04) >> 2
			d['syn']=(ord(s[33]) & 0x02) >> 1
			d['fin']=(ord(s[33]) & 0x01) 
			d['window_size']=socket.ntohs(struct.unpack('H',s[34:36])[0])
			d['tcp_chksm']=socket.ntohs(struct.unpack('H',s[36:38])[0])
			d['urg_ptr']=socket.ntohs(struct.unpack('H',s[38:40])[0])
		elif protocols[d['protocol']]=='udp':
			d['source_port']=socket.ntohs(struct.unpack('H',s[20:22])[0]) 
			d['destination_port']=socket.ntohs(struct.unpack('H',s[22:24])[0])
			d['udp_length']=socket.ntohs(struct.unpack('H',s[24:26])[0])
			d['udp_chksm']=socket.ntohs(struct.unpack('H',s[26:28])[0])
		elif protocols[d['protocol']]=='icmp':
			d['type']=ord(s[20])
			d['code']=ord(s[21])
			d['icmp_chksm']=socket.ntohs(struct.unpack('H',s[22:24])[0])
		
    		if d['header_len']>5:
    		    d['options']=s[20:4*(d['header_len']-5)]
    		else:
    		    d['options']=None
    		    d['data']=s[4*d['header_len']:]
    		return d
	
	
	def decode_arp_packet(self,s):
    		d={}
    		d['hardware_type']=socket.ntohs(struct.unpack('H',s[0:2])[0])
    		d['protocol_type']='IPv4'
    		d['MAC_length']=ord(s[4])
    		d['ip_length']=ord(s[5])
    		d['op_code']=socket.ntohs(struct.unpack('H',s[6:8])[0])
    		d['source_hardware_address1']=ord(s[8])
    		d['source_hardware_address2']=ord(s[9])
    		d['source_hardware_address3']=ord(s[10])
    		d['source_hardware_address4']=ord(s[11]) 
    		d['source_hardware_address5']=ord(s[12])
    		d['source_hardware_address6']=ord(s[13]) 
    		d['source_ip_address']=pcap.ntoa(struct.unpack('i',s[14:18])[0])
    		d['destination_hardware_address1']=ord(s[18])
    		d['destination_hardware_address2']=ord(s[19])
    		d['destination_hardware_address3']=ord(s[20])
    		d['destination_hardware_address4']=ord(s[21])
    		d['destination_hardware_address5']=ord(s[22])
   		d['destination_hardware_address6']=ord(s[23])
   
   		d['destination_ip_address']=pcap.ntoa(struct.unpack('i',s[24: 28])[0])
    		return d


	def hex2dec(self,string_num):
    		return int(string_num.upper(), 16)

  

	def print_and_save_packet(self,pktlen, data, timestamp,b,num):
    		if not data:
        		return
		
    		file_object = open(r'/home/py_sniff/'+b+'/'+str(num)+'.txt','wb')
    		file_object.write('No.'+str(num)+' packet information\n')

    		arrive_time=time.strftime('%Y-%m-%d %X', time.localtime() )
    		file_object.write('%s%s\n' %('time:',arrive_time))
		
		#ethernet head
   		print "destination_hardware_address:",
   		print "%02x:" % ord(data[0]),
    		print "%02x:" % ord(data[1]),
    		print "%02x:" % ord(data[2]),
    		print "%02x:" % ord(data[3]),
    		print "%02x:" % ord(data[4]),
    		print "%02x" % ord(data[5])
    		print "source_source_hardware_address:",
    		print "%02x:" % ord(data[6]),
    		print "%02x:" % ord(data[7]),
    		print "%02x:" % ord(data[8]),
    		print "%02x:" % ord(data[9]),
    		print "%02x:" % ord(data[10]),
    		print "%02x" % ord(data[11])
    		file_object.write('%s%02x:%02x:%02x:%02x:%02x:%02x\n'%('des:',ord(data[0]),ord(data[1]),ord(data[2]),ord(data[3]),ord(data[4]),ord(data[5])))
    		file_object.write('%s%02x:%02x:%02x:%02x:%02x:%02x\n'%("src:",ord(data[6]),ord(data[7]),ord(data[8]),ord(data[9]),ord(data[10]),ord(data[11])))
		#arp pkt
		if data[12:14]=='\x08\x06':
			decoded=self.decode_arp_packet(data[14:])
			print '%s.%f %s > %s' % (time.strftime('%H:%M',time.localtime(timestamp)),timestamp % 60,decoded['source_ip_address'],decoded['destination_ip_address'])
			file_object.write('%s%s\n' %('srcip:',decoded['source_ip_address']))
        		file_object.write('%s%s\n' %('desip:',decoded['destination_ip_address']))
			#
			real_source=str(decoded['source_ip_address'])
			real_destination=str(decoded['destination_ip_address'])
			for key in ['hardware_type','protocol_type','MAC_length','ip_length','op_code']:
				print '    %s: %s' % (key, decoded[key])
				file_object.write('%s:%s\n'% (str(key),str(decoded[key])))
			#
			protocol_type=''
			protocol_type=protocol_type+'ARP:'+decoded['protocol_type']
			pkt_length=str(decoded['ip_length'])
			information=''
        		print 'source_mac_address:',
        		for key in ['source_hardware_address1','source_hardware_address2','source_hardware_address3','source_hardware_address4','source_hardware_address5']:
            			print '%02x:'% decoded[key],    
        		print '%02x'%decoded['source_hardware_address6']

        		file_object.write('%s:'%'srcMac')
        		for key in['source_hardware_address1','source_hardware_address2','source_hardware_address3','source_hardware_address4','source_hardware_address5']:
            			file_object.write('%02x:'% decoded[key]) 
				#
				information=information+str(hex(decoded[key])[2:3])+':'
        		file_object.write('%02x\n'% decoded['source_hardware_address6'])
			#
			information=information+str(hex(decoded['source_hardware_address6'])[2:3])
			information=information+'-->'
			

			
        
        		print "destination_mac_address:",
        		for key in ['destination_hardware_address1','destination_hardware_address2','destination_hardware_address3','destination_hardware_address4','destination_hardware_address5']:
            			print '%02x:' % decoded[key],
        		print '%02x' % decoded['destination_hardware_address6']
        
        		file_object.write('%s:'%"desMac")
        		for key in ['destination_hardware_address1','destination_hardware_address2','destination_hardware_address3','destination_hardware_address4','destination_hardware_address5']:
            			file_object.write('%02x:'% decoded[key]) 
				information=information+str(hex(decoded[key])[2:3])+':'
        		file_object.write('%02x\n'% decoded['destination_hardware_address6'])
			information=information+str(hex(decoded['destination_hardware_address6'])[2:3])

        		print 'protocol: ARP' 
        		file_object.write('%s:%s\n'%('protocol','ARP'))
				
            	#ip pkt
    		elif data[12:14]=='\x08\x00':
        		decoded=self.decode_ip_packet(data[14:])
       			print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                decoded['destination_address'])
        		file_object.write('%s%s\n' %('src:',decoded['source_address']))
        		file_object.write('%s%s\n' %('des:',decoded['destination_address']))
     			#return to tablewidget
			real_source=str(decoded['source_address'])
			real_destination=str(decoded['destination_address'])
			#write in txt
        		for key in ['version', 'header_len','total_len', 'id',
                                'flags', 'fragment_offset', 'ttl']:
            			print '    %s: %d' % (key, decoded[key])
            		file_object.write('%s:%s\n'%(str(key),str(decoded[key])))
			
        		print '    protocol: %s' % protocols[decoded['protocol']]
        		file_object.write('%s:%s\n'%('protocol',protocols[decoded['protocol']]))
			#return to tablewidget
			protocol_type=protocols[decoded['protocol']]
			pkt_length=str(decoded['total_len'])
			information=''

        		print '    header checksum: %d' % decoded['checksum']
        		file_object.write('%s:%s\n'%('hdchks',str(decoded['checksum'])))
			if protocols[decoded['protocol']]=='tcp':
				#d['source_port']==socket.ntohs(struct.unpack('H',s[20:22])[0]) 
				print '    source_port: %d' % decoded['source_port']
        			file_object.write('%s:%s\n'%('src_port',str(decoded['source_port'])))
				#d['destination_port']==socket.ntohs(struct.unpack('H',s[22:24])[0]) 
				print '    destination_port: %d' % decoded['destination_port']
        			file_object.write('%s:%s\n'%('des_port',str(decoded['destination_port'])))
				#d['send_order']=socket.ntohs(struct.unpack('l',s[24:28])[0])
				print '    send_order: %s' % decoded['send_order']
        			file_object.write('%s:%s\n'%('sd_ord',str(decoded['send_order'])))
				#d['def_oder']=socket.ntohs(struct.unpack('l',s[28:32])[0])
				print '    def_order: %s' % decoded['def_order']
        			file_object.write('%s:%s\n'%('df_ord',str(decoded['def_order'])))
				information='port:'+str(decoded['source_port'])+'-->'+'port:'+str(decoded['destination_port'])
				#d['urg']=(ord(s[33]) & 0x20) >> 5
				print '    urg: %s' % decoded['urg']
        			file_object.write('%s:%s\n'%('urg',str(decoded['urg'])))
				#d['ack']=(ord(s[33]) & 0x10) >> 4
				print '    ack: %s' % decoded['ack']
        			file_object.write('%s:%s\n'%('ack',str(decoded['ack'])))
				#d['psh']=(ord(s[33]) & 0x08) >> 3
				print '    psh: %s' % decoded['psh']
        			file_object.write('%s:%s\n'%('psh',str(decoded['psh'])))
				#d['rst']=(ord(s[33]) & 0x04) >> 2
				print '    rst: %s' % decoded['rst']
        			file_object.write('%s:%s\n'%('rst',str(decoded['rst'])))
				#d['syn']=(ord(s[33]) & 0x02) >> 1
				print '    syn: %s' % decoded['syn']
        			file_object.write('%s:%s\n'%('syn',str(decoded['syn'])))
				#d['fin']=(ord(s[33]) & 0x01) 
				print '    fin: %s' % decoded['fin']
        			file_object.write('%s:%s\n'%('fin',str(decoded['fin'])))
				#d['window_size']=socket.ntohs(struct.unpack('H',s[34:36])[0])
				print '    window_size: %s' % decoded['window_size']
        			file_object.write('%s:%s\n'%('wd_sz',str(decoded['window_size'])))
				#d['tcp_chksm']=socket.ntohs(struct.unpack('H',s[36:38])[0])
				print '    tcp_chksm: %s' % decoded['tcp_chksm']
        			file_object.write('%s:%s\n'%('t_chksm',str(decoded['tcp_chksm'])))
				#d['urg_ptr']=socket.ntohs(struct.unpack('H',s[38:40])[0])
				print '    urg_ptr: %s' % decoded['urg_ptr']
        			file_object.write('%s:%s\n'%('urg_ptr',str(decoded['urg_ptr'])))
			elif protocols[decoded['protocol']]=='udp':
				#d['source_port']==socket.ntohs(struct.unpack('H',s[20:22])[0]) 
				print '    source_port: %d' % decoded['source_port']
        			file_object.write('%s:%s\n'%('src_p',str(decoded['source_port'])))
				#d['destination_port']==socket.ntohs(struct.unpack('H',s[22:24])[0]) 
				print '    destination_port: %d' % decoded['destination_port']
        			file_object.write('%s:%s\n'%('des_p',str(decoded['destination_port'])))
				#d['send_order']=socket.ntohs(struct.unpack('H',s[24:28])[0])
				information='port:'+str(decoded['source_port'])+'-->'+'port:'+str(decoded['destination_port'])
				#d['udp_length']=socket.ntohs(struct.unpack('H',s[24:26])[0])
				print '    udp_length: %d' % decoded['udp_length']
        			file_object.write('%s:%s\n'%('udp_length',str(decoded['udp_length'])))
				#d['udp_chksm']=socket.ntohs(struct.unpack('H',s[26:28])[0])
				print '    udp_chksm: %d' % decoded['udp_chksm']
        			file_object.write('%s:%s\n'%('udp_chksm',str(decoded['udp_chksm'])))
			elif protocols[decoded['protocol']]=='icmp':
					#d['type']=ord(s[20])
				print '    type: %d' % decoded['type']
        			file_object.write('%s:%s\n'%('type',str(decoded['type'])))
					#d['code']=ord(s[21])
				print '    code: %d' % decoded['code']
        			file_object.write('%s:%s\n'%('code',str(decoded['code'])))
					#d['icmp_chksm']=socket.ntohs(struct.unpack('H',s[22:24])[0])
				print '    icmp_chksm: %d' % decoded['icmp_chksm']
        			file_object.write('%s:%s\n'%('icmp_chksm',str(decoded['icmp_chksm'])))
        		print '    data:'
        		file_object.write('data\n')
        		file_object.write('-'*80)
        		file_object.write("\n%-010s||%-050s||%-020s\n" % ('segment','bytes','ascii'))
        		bytes = map(lambda x: '%.2x' % x, map(ord, decoded['data']))
        		chrs=[]      
        		i=0              
        		for j in xrange(0,len(bytes)-1):
        			chrs.append(chr(self.hex2dec(bytes[j])))
        		for i in xrange(0,(len(bytes)/16)-1):
        			print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
        			file_object.write("%-010s||%-050s||%-020s\n" % (str(i*10),string.join(bytes[i*16:(i+1)*16],' '),string.join(chrs[i*16:(i+1)*16],'')))
        			print '        %s' % string.join(chrs[i*16:(i+1)*16],'')
        		print '        %s' % string.join(bytes[(i+1)*16:],' ')
        		print '        %s' % string.join(chrs[i*16:(i+1)*16],'')
        		file_object.write("%-010s||%-050s||%-020s\n" % (str(i*10),string.join(bytes[(i+1)*16],' '),string.join(chrs[(i+1)*16],'')))
    		file_object.close()
		return (arrive_time,real_source,real_destination,protocol_type,pkt_length,information)


	def patch_a_packet(self,p):
    		i=0
    		while i<1:
	    		#print p.next()	
	    		b=p.next()
	    		if(b!=None):
		    		i=i+1
    		#tuple(pktlen, data, timestamp)=p.next()
    		return b

	def run(self):
		p = pcap.pcapObject()
    		#self.test_findalldevs()
    
    		#dev = pcap.lookupdev()
    		#dev = raw_input("please select an interface shown above:")
    		print 'run:',self.devi
    		net, mask = pcap.lookupnet(str(self.devi))
   		p.open_live(str(self.devi), 1600, 0, 100)
    		#rule=raw_input("please input your filtering rule:(protocol port num):")

		#rule should be given in filter
		#so self.ruleString might ....
		rule=str(self.filter_rule)
		print 'rule:'+rule
    		p.setfilter(rule,0,0)

    		try:
        		
    			if os.path.exists('/home/py_sniff/'+self.documentPath)==False:
				os.makedirs(r'/home/py_sniff/'+self.documentPath)
        		pkt_number=0
        		while 1:
            			dispatch_tuple=self.patch_a_packet(p)
            			if(dispatch_tuple!=None):
                			pkt_number=pkt_number+1
               				print '['+str(pkt_number)+']\n'
                			#print dispatch_tuple
            				#one packet one txt
            				(a,b,c,d,e,f)=self.print_and_save_packet(dispatch_tuple[0],dispatch_tuple[1],dispatch_tuple[2],self.documentPath,pkt_number)
            				print '==================================================='
#!!!!!!!!!!!!!!!!!!!!!addItem
					#stamp,source,destination,protocol,length,information
					
					self.emit(QtCore.SIGNAL('CAPTURE_ONE_PACKET'),pkt_number,a,b,c,d,e,f)
    		except KeyboardInterrupt:
        		print '%s' % sys.exc_type
        		print 'shutting down'
       			print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()

#filter_dialog
class Ui_Dialog(QtGui.QDialog):
    def __init__(self, parent=None):
	#print 'initial filter'
	QtGui.QWidget.__init__(self,parent)
	self.resize(200,200)  
	self.setWindowTitle('filter') 
	
	self.grammar=QtGui.QLabel("port")
	self.grammar.setText("Please enter filter rule\nGrammar: [protocol] ... or [protocol](port number)\n(ether)src/dst +ip/mac")
       	self.sentence = QtGui.QLineEdit()
   	
	self.sure=QtGui.QPushButton('OK')  
        self.connect(self.sure,QtCore.SIGNAL('clicked()'),self.ok)   
	grid=QtGui.QGridLayout()  
	grid.addWidget(self.sentence,1,0,2,1) 
	grid.addWidget(self.grammar,1,0,1,1) 
	grid.addWidget(self.sure,1,0,3,1) 
	self.setLayout(grid)  
    def ok(self):
	print 'ok'
	#print self.sentence.displayText()
	filterRule=self.sentence.displayText()
	self.emit(QtCore.SIGNAL('RULE_GET'),filterRule)
	#print filterRule

if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    MainWindow = QtGui.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

