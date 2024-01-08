---
layout: page
icon: fas fa-book
order: 1
---

<div id="post-list">

{% for post in site.posts %}
  {% if post.category == "blogpost" %}
  <div class="post-preview">
    <h1>
      <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
    </h1>

    <div class="post-content">
      <p>
        {% include no-linenos.html content=post.description %}
        {{ content | markdownify | strip_html | truncate: 200 }}
      </p>
    </div>

    <div class="post-meta text-muted d-flex">

      <div class="mr-auto">
        <!-- posted date -->
        <i class="far fa-calendar fa-fw"></i>
        {% include timeago.html date=post.date tooltip=true capitalize=true %}

        <!-- time to read -->
        <i class="far fa-clock fa-fw"></i>
        {% include read-time.html content=post.content %}
      </div>

    </div> <!-- .post-meta -->

  </div> <!-- .post-review -->
  {% endif %}
{% endfor %}

</div> <!-- #post-list -->