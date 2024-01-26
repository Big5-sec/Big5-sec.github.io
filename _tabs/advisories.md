---
layout: page
title: Advisories
icon: fas fa-bug
order: 2
---
The following vulnerabilities were found through original research.

{% assign sorted = site.posts | sort: 'date_cve' | reverse %}

<br/>
<table>
<thead>
  <tr><th>Date</th><th>CVE</th><th>Title</th></tr>
</thead>
<tbody>
{% for post in sorted %}
  {% if post.inadvisory == true %}
  <tr>
    <td>{{ post.date_cve }}</td>
    <td>{{ post.cve }}</td>
    <td>{{ post.advisory_title }}</td>
    <td>
      {% if post.details_ok == true %}
        <a href="{{ post.url | relative_url }}">details</a>
      {% else %}
        details incoming...
      {% endif %}
    </td>
  </tr>
  {% endif %}
{% endfor %}

</tbody>
</table>
