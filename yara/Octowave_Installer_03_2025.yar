rule Octowave_Installer_03_2025
{
    meta:
        description = "Detects resources embedded within Octowave Loader MSI installers"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-28"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "05b025b8475c0acbc9a5d2cd13c15088a2fb452aa514d0636f145e1c4c93e6ee"
        hash2 = "39d4ddd455296d29ac98a431e5049950763b77f111c5b65f9c82a5b669898e75"
        hash3 = "76efc8c64654d8f2318cc513c0aaf0da612423b1715e867b4622712ba0b3926f"
        hash4 = "500462c4fb6e4d0545f04d63ef981d9611b578948e5cfd61d840ff8e2f206587"
        hash5 = "d7816ba6ddda0c4e833d9bba85864de6b1bd289246fcedae84b8a6581db3f5b6"
        hash6 = "c51c230e0504d92de1358f2f6772a6e5abe6dd205bbc6a2ef5f5561bb4b02c6d"
        hash7 = "5ee9e74605b0c26b39b111a89139d95423e54f7a54decf60c7552f45b8b60407"
        hash8 = "2e43fbeabfe519e9f034762745746b3213ce5dd4163a9ca9910b6782bd2f4e6a"
        hash9 = "0f80a7a6588520e9c5f4616a35cacc1365fdb2eea47d415f0f18e8c963a54f95"
        hash10 = "9ff3b5c7f9b03e7a54a4cd53249ccd618a171555c177c7e3f1a41c2fe21604f4"
        hash11 = "c3e2af892b813f3dcba4d0970489652d6f195b7985dc98f08eaddca7727786f0"
        id = "56685a0a-523d-4060-a008-aa28542cb85c"
    strings:
        $resource_id1 = "fil027F8070E5296A7A6BE029B225291BE6" ascii
        $resource_id2 = "fil1E34AA08E451E369856CB0A4F2C939EE" ascii
        $resource_id3 = "fil297E950E869CCEDDB75446F8D36E6BB2" ascii
        $resource_id4 = "fil31195C8B4D586EF2F6AEDBB7DA019DD4" ascii
        $resource_id5 = "fil3CCA13E37F6C0FBAAB75A40C6636F239" ascii
        $resource_id6 = "fil4A31A9B03857A7D76210669A62EC7A80" ascii
        $resource_id7 = "fil74D5978E2A1696BB7C6088D8DD956363" ascii
        $resource_id8 = "filB51934D37AB360C1AEEC726418A8D2C0" ascii
        $resource_id9 = "filE57E1C016BB2D8019E11BAD25E9F27E9" ascii
        $resource_id10 = "filFC2613A65AB6F588ADEB6192ED21091A" ascii
        $resource_id11 = "fil010C01AC70711389D6F3F44F66D6F960" ascii
        $resource_id12 = "filF1080A54EDC901AD8472E8810472E8D1" ascii
        $resource_id13 = "filE8053A5754447918EBF42AC78C3AF82E" ascii
        $resource_id14 = "filB4F71B4429FDCAF793DC10D1D191A726" ascii
        $resource_id15 = "fil1642099F01F2701D029339F3046DC665" ascii
        $resource_id16 = "fil7CB6BE22591264EA960A5764C04D6DA1" ascii
        $resource_id17 = "fil0CF1E9B7AFD0F7BADA83ECE0E4E07807" ascii
        $resource_id18 = "fil1A867C9CAC9095C6B38E26CF088C07FD" ascii
        $resource_id19 = "fil1B9130C416BDFAD71552D6737D938104" ascii
        $resource_id20 = "fil1D5ACCB567BE6D9F541AF616D2A39700" ascii
        $resource_id21 = "fil346B5BFF8F702E0A87881E08D0A4BD16" ascii
        $resource_id22 = "fil3BB21646333C6FAEDFEB23AE71E7A429" ascii
        $resource_id23 = "fil41694C9A733ECAE0FEE52F52034236A2" ascii
        $resource_id24 = "fil49C1F80B1F6FE96356E46A38C2A48824" ascii
        $resource_id25 = "fil5BB45178BB9B867C09A764301CAD906B" ascii
        $resource_id26 = "fil614D6A12C99CBC7C60F76948CB2BE671" ascii
        $resource_id27 = "fil639CE28713582712800A308359F89B34" ascii
        $resource_id28 = "fil73CBB0582F4A457ADC72C2C205A007F2" ascii
        $resource_id29 = "fil77D36FE7D05CC67091656D82F3715294" ascii
        $resource_id30 = "fil7F79365F4BC03C141E783EF1A8A2E48C" ascii  
        $resource_id31 = "fil7FE77EEB3ECECD7917F7FD20FE522BBE" ascii  
        $resource_id32 = "fil88E06B77520C1765D8D6DE64E2F67F35" ascii  
        $resource_id33 = "fil7FEF2F54FB68D5EB871C3D96CF9F41F3" ascii  
        $resource_id34 = "filA716A755F8CA46379F012E0EA777D1E9" ascii  
        $resource_id35 = "filA7CC95B64BD02996F55D5312C6B15D84" ascii  
        $resource_id36 = "filC90F0BB67F0352C06F448C6435A3D5BD" ascii  
        $resource_id37 = "filD3C33C735B075954B8478688E2D287F3" ascii  
        $resource_id38 = "filDAC6D2E1339413E27812F267D2119F09" ascii  
        $resource_id39 = "filE247DFA527D004A6DE8E511EAEEE2574" ascii  
        $resource_id40 = "filEC051872504D8D8D0708EC53BFBE2734" ascii  
        $resource_id41 = "filF1080A54EDC901AD8472E8810472E8D1" ascii     
        
    condition:
        (uint32(0) == 0xe011cfd0)
        and filesize < 200000KB
        and 4 of them
}