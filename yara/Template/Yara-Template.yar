/*
   You can add any other notes if required up in this section
*/

rule ENTER_UNIQUE_NAME {
	meta:
		description = "" // Add a description of what you're attempting to detect with this rule
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE" // Add a license for your rule or keep it this
		author = "" // Add your name
		reference = "" // Add any references used
		date = "" // Add the date of creation or modification
	strings:
		$string1 = "" // Add relevant strings if used like this
		$bytes1 = {} // Add relevant bytes if used like this
	condition:
		filesize < 1000KB and (uint16(0) == 0x5a4d) and (X of them) // change `X` to the number of strings you wish to match, alter the relevant file size, and add any other conditions
}