rule Octowave_Installer_03_2025
{
    meta:
        description = "Detects resources embedded within Octowave Loader MSI installers"
        author = "Jai Minton (@CyberRaiju) - HuntressLabs"
        date = "2025-03-28"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        yt_reference = "https://www.youtube.com/watch?v=NiNIbkiuExU"
        reference = "https://x.com/CyberRaiju/status/1893450184224362946?t=u0X6ST2Qgnrf-ujjphGOSg&s=19"
        hash1 = "4be1f385cb4c1bc4d055568807a8d632c0e550184817fcdb602d1a75134336f9"
        hash2 = "05b025b8475c0acbc9a5d2cd13c15088a2fb452aa514d0636f145e1c4c93e6ee"
        hash3 = "39d4ddd455296d29ac98a431e5049950763b77f111c5b65f9c82a5b669898e75"
        hash4 = "76efc8c64654d8f2318cc513c0aaf0da612423b1715e867b4622712ba0b3926f"
        hash5 = "500462c4fb6e4d0545f04d63ef981d9611b578948e5cfd61d840ff8e2f206587"
        hash6 = "d7816ba6ddda0c4e833d9bba85864de6b1bd289246fcedae84b8a6581db3f5b6"
        hash7 = "c51c230e0504d92de1358f2f6772a6e5abe6dd205bbc6a2ef5f5561bb4b02c6d"
        hash8 = "5ee9e74605b0c26b39b111a89139d95423e54f7a54decf60c7552f45b8b60407"
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

    condition:
        (uint32(0) == 0xe011cfd0)
        and filesize < 200000KB
        and 4 of them
}