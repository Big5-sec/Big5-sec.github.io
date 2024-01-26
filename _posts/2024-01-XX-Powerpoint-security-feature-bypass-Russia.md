---
layout: post
title:  URI schemes-based attacks through Microsoft Office - An analysis of a Russian-nexus adversary malicious Powerpoint document and the associated vulnerability that went off-the-radar
date:   2023-08-18 22:50:40 +0100
img_path: /assets/img/2023-08-18-CVE-2023-29360-analysis/
description: an analysis of the root cause of this vulnerability, where MDLs are in play  
category: blogpost
---

# Introduction

URI schemes-based attacks through Microsoft Office gained a lot of traction following the publication of CVE-XXX-XXX and CVE-2021-40444 (Follina). More recently, the ms-search URI scheme was abused to drop a file at a predetermined location within the exploit chain labeled as CVE-2023-XXXX. 
When I joined CrowdStrike in September 2022, one of the first analyses I did was to investigate such an attack, which went off-the-radar for multiple reasons such as the fact this attack is certainly harder to pull off than a RCE in Microsoft Word. While this attack is quite old, this blogpost details it and explains one of the vulnerability exploited in the process, that got patched without any associated CVE. Hopefully some people will still find it interesting.

# Attack Description

his document makes use of a url scheme of the following form ````[space][space][space][space][space][space].vbs:%2E%2E\%2E%2E\%2E%2E\%2E%2E\%2E%2E\%2E%2E\%2E%2E\%2E%2E\windows/System32::$index_allocation/SyncAppvPublishingServer.vbs [...]````,in an hyperlink attached to a shape with the "on mouse-over event". While seeing the document in slideshow, moving the mouse triggers the "on mouse-over event", that will triggers itself the navigation to the hyperlink. Finally, in the end, this navigation would run the vbs script.


The executed PowerShell downloads a next-stage payload from a file named DSC0002.jpeg hosted on a OneDrive URL (with the hostname 9b5uja.am.files.1drv[.]com; the full URL is provided in the Indicators of Compromise section). The file contains an obfuscated PE DLL that the PowerShell decodes using a XOR cipher whose key is generated using a linear congruential generator (LCG), as follows:

$payload = $payload[4 .. $payload.Count];
$key = 24;

$payload = $payload | %{$key=(29*$key+49)%256; $_=($_ -bxor $key); $_};

The resulting DLL is written to %ALLUSERPROFILE%\lmapi2.dll and persisted using a COM Hijacking auto-start execution point (ASEP). The written Registry key is HKCU\Software\Classes\CLSID\{2735412E-7F64-5B0F-8F00-5D77AFBE261E}\InProcServer32, which is normally used by the legitimate Microsoft IMAPI v2. The chosen COM object and installation filename are consistent, although the adversary chose to typosquat the name by replacing the capital i with an l in the filename.

The decrypted lmapi2.dll DLL is tracked as Korobka. It is a downloader for an encrypted shellcode, hosted on OneDrive as DSC0001.jpeg (with a URL hosted on kdmzlw.am.files.1drv[.]com; the full URL is provided in the Indicators of Compromise section). The downloader uses a hard-coded RSA key to decrypt a AES symmetric key stored at the beginning of DSC0001.jpeg, which it uses to decrypt a shellcode. The decrypted shellcode is preceded by a per-deployment DWORD magic value equal to 0x45653eed.

The decrypted shellcode is consistent with that observed in CSA-211123. It loads an updated version of the Graphite backdoor.

# Within the associated "Office security feature bypass" 


From an hyperlink activation in Powerpoint to the execution of vbs file, the flow of the execution goes through at least 3 different components of the Windows operating system:

1. The hyperlink that has been parsed by Powerpoint is activated inside it. Powerpoint will take the first actions to know how to treat it and check if this is valid.
2. The flow of execution is then transferred to the hlink.dll library, that will do the necessary to prepare the third step.
3. The flow of execution is transferred to the shell32.dll library through a call to the ShellExecute function.
4. Optional - Based on the type of URL, any number of additional Windows systems may be then involved. _(please note this is not always the case based on the url scheme used)_
 
While the execution flow is inside the first component, Powerpoint, It will goes through the following functions in order:

1. ``mso!MsoHrHlinkNavigateEx``
2. ``mso!MsoHrHlinkNavigateBase``
3. ``mso30win32client!MsoHrSafeToNavigateEx``
4. ``mso!MsoHrHlinkCheckStringReferenceEx``

The latter is responsible to bring a security popup to the user based on the results of the ``Mso::DoNotUse::UrlSafety::CheckUrlSafety`` function. Inside this function, two checks are performed in our case to determine if the URL is safe or not.

1. the first one that checks if the protocol is considered safe, with the function ``Mso::DoNotUse::UrlSafety::HrCheckProtocolNavigation``
2. the second one that checks the url zone of the hyperlink target, with the function ``Mso::DoNotUse::UrlSafety::HrCheckZoneNavigation``

While the second checks would logically not raise any security warning because we are targeting a local file on the system, it appears strange that ``.vbs`` is not considered malicious by the 
``Mso::DoNotUse::UrlSafety::HrCheckProtocolNavigation` function.

Inside this function, with the associated ".vbs" url, we have:
1. a call to ``CMsoUrlSimple::HrIsSafeProtocol`` that returns an error (E_FAIL). **Here, in the case we have an error, we do nothing and continue the execution of the function**.
2. a call to ``Mso::DoNotUse::UrlSafety::FIsTrustedProtocol`` that returns ``False`` as expected.
3. a call to ``CMsoUrlSimple::FIsLocal`` that returns ``True`` as expected.

Because the results of the call to ``CMsoUrlSimple::HrIsSafeProtocol`` are not checked against any error, only the result of ``CMsoUrlSimple::FIsLocal`` counts here. So, our ``.vbs:`` URL scheme which is obviously not a safe protocol would not raise any security popup. 

So in the end, any *strange* protocol will be considered as safe as long as the target of the hyperlink is local. Crowdstrike do believe this should not be the case as attacks through local scripts or custom protocol handlers could potentially still be effective (even with security measures implemented inside hlink, ieframe and shell32).
