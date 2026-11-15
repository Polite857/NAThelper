# NAThelper
  支持WindowsNT4.0/Windows95的NAT穿透软件，可以让有NAT1但没有公网IP（路由器WAN口显示内网IP）的用户在公网地址上打洞，从而让BT高速下载或开放服务变得可能
  
  带有UPnP支持，对于CGNAT（运营商NAT）场景下，我们常常可以用NAT检测软件看到NAT1，但是这种NAT1和有公网IP然后设置DMZ得到的NAT1并不一样，在CGNAT场景下，本机开放的端口和实际在公网上开放的端口并不一致，并且NAT表是动态的，只有该端口向外发出请求后，运营商设备才会建立内部端口到外部公网端口的映射关系，超过一段时间没有连接后就会回收
  
  为了解决这一问题，本软件利用STUN服务器让运行了NAThelper的客户端知道自己的公网IP和CGNAT设备开放出去的端口，在映射连接建立时会选择一个本地端口和服务端口，比如BT客户端使用了1234端口监听传入连接，用户就设置1234端口为服务端口，然后随意挑选111作为本地端口，映射建立后可以看到外部端口号为23456，随后将BT客户端的监听端口号改为23456，NAThelper的服务端口也改为23456，本地端口不变（本地端口变化后外部端口号也会变）并在服务端口和本地端口之间进行端口转发，这样其他BT客户端在Tracker服务器上看到我们的BT客户端登记的公网IP和端口号后，就可以直接与我们的BT客户端建立连接了。
  
  程序分为三个版本，NAThelper、NAThelp32、NAThelp9X，NAThelper适用于Windows Vista x64或更新的系统，NAThelp32适用于Windows NT4.0 SP5或更新的系统，NAThelp9X适用于Windows 95/98/Me，为了让软件性能更好请在系统要求满足的情况下尽可能选择更高级的版本
  
<img width="640" height="480" alt="d17d3f0861e26e4c60cd005f5e58eb43" src="https://github.com/user-attachments/assets/57618f23-4cee-41b3-971f-389072f0cb96" />
<img width="640" height="480" alt="a6f28c2a5bf5d3667a40268917f29ed8" src="https://github.com/user-attachments/assets/18d3e44d-4d0a-4ea4-9a6a-3c5249ff08aa" />
<img width="1122" height="762" alt="1c0b1058adea880860b99f10cecabbe4" src="https://github.com/user-attachments/assets/6aa78371-e506-429e-8c5a-e28bd2270b24" />
<img width="1024" height="768" alt="533249f2219fb2c0d97fbcaf146b149b" src="https://github.com/user-attachments/assets/e6fcebcf-154e-4c2f-b7f5-444d682c0384" />
