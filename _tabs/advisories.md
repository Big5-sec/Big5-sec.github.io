---
layout: page
title: Advisories
icon: fas fa-bug
order: 2
---
<div id="post-list">

{% for post in site.posts %}
  {% if post.category == "advisory" %}
  <div class="post-preview">
    <h1>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </h1>
  </div> <!-- .post-review -->
  {% endif %}
{% endfor %}

</div> <!-- #post-list -->