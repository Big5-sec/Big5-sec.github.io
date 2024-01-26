---
layout: post
title:  BrikerBox and Briker IPPBX SQL injection
date:   2024-01-25 22:50:40 +0100
category: advisory
inadvisory: true
cve: partial 0day
advisory_title: BrikerBox and Briker IPPBX SQL injection
date_cve: 2024-08-23
details_ok: true
---

# Details

At the start of August, an advertisement popped on cybercrime forums for a 0day affecting both the open-source and the paid version ([Brikerbox](https://itmn.co.id/brikerbox/ar1500s/)) of the [Briker IPPBX](https://www.briker.org/) software, used mostly in Indonesia. Following more in-depth investigation, it was possible to uncover the vulnerability:

In the `/var/www/apps/ippbx/recordings/includes/main.conf.php` file (reachable directly), there is a SQLi at line 76: 

```php
$db_query = "SELECT password FROM mi_tblUser WHERE status='2' AND username = '".$_POST['username']."";
```

As this file is part of the login flow, it allows for unauthenticated attack, in particular against the following endpoints: 

- ``/apps/ippbx/recordings/recordings.php``
- ``/apps/userportal/userportal.php`` -> authentication page of the appliance

Users credentials being stored in clear text in the database, using SQLi to obtain an admin account is straightforward.

BrikerBox vendor was contacted late August 2023. Previously exposed instances appear unreachable anymore. Still, Brikker IPPBX- the open-source version- is still vulnerable.