---
title: Wordpress SQL注入分析（一）
date: 2017-09-02 00:50:59
tags: 漏洞分析
---

作者：Ambulong@vulspy

* [Wordpress SQL注入分析（一）](/2017/09/02/Wordpress-SQL-Injection-Analysis-1/)
* [Wordpress SQL注入分析（二）](/2017/09/03/Wordpress-SQL-Injection-Analysis-2/)

## 第一章: sprintf/vsprintf 中的 argument numbering/swapping

### 1.1 函数间的区别
在PHP中，我们主要通过sprintf函数和vsprintf函数来格式化字符串，同时会对参数进行类型的转换。这两个函数的区别在于sprintf函数在第一个参数之后可接收多个不同类型参数，vsprintf的第一个参数之后只接收一个数组参数（即：第二个参数只能是数组）。

**sprintf函数**
```php
string sprintf ( string $format [, mixed $args [, mixed $... ]] )
```

**vsprintf函数**
```php
string vsprintf ( string $format , array $args )
```

### 1.2 format参数

sprintf/vsprintf函数的第一个参数$format指定了如何格式化后面的参数。
常见的格式化类型如下：

标识	|类型
--------|------
%s	|字符串
%d	|整数
%f	|浮点数

以下两个例子的输出结果是一样的

```php
//例一
echo sprintf("str:%s int:%d float:%f", '123.123aa', '123.123aa', '123.123aa');
//例二
echo vsprintf("str:%s int:%d float:%f", array('123.123aa', '123.123aa', '123.123aa'));
```
输出结果:
```
str:123.123aa int:123 float:123.123000
```

### 1.3 format参数延伸

**sprintf/vsprintf函数还可以用来将字符串自动补位**，如:
 
例一："123"用0补齐5位变成"00123":
```php
echo sprintf("%05d", '123');
```
0表示要补上的数字为0，5表示的是位数，d表示类型为整数。

例二："123"用.补齐5位变成"..123":
```php
echo sprintf("%'.5d", '123');
```
'.表示要补上的字符为。(字符需要加上')，5表示的是位数，d表示类型为整数。


*需要了解更多关于format的描述，请参见 [sprintf()](http://php.net/manual/zh/function.vsprintf.php)*

**Argument numbering/swapping**

sprintf/vsprintf的格式化字符串支持**Argument numbering/swapping**（中文直译：参数交换），即可以指定格式化标识表示的是第几个参数。
例一：
```php
echo sprintf('%2$s %3$s %1$s', 'a1', 'a2', 'a3');
//输出：a2 a3 a1
```
例二：
```php
echo sprintf('%s %s %1$s', 'a1', 'a2', 'a3');
//输出：a1 a2 a1
```
例三：
```php
echo sprintf('%s %s %1$\'.5s', 'a1', 'a2', 'a3');
//输出：a1 a2 ...a1
```

*注：Chapter 1由[@Ambulong](http://blog.vulspy.com/)与[@乐清小俊杰](http://yqxiaojunjie.com/)共同完成。*

## 第二章: wpdb类中的prepare()函数

在Wordpress的数据库操作类wpdb(文件: [/wp-includes/wp-db.php](https://github.com/WordPress/WordPress/blob/bbb8d48086b7d10908f4fda673585ee122f2851d/wp-includes/wp-db.php#L1228))中有一个prepare()函数，该函数主要用来对将要执行SQL语句进行预处理，如：
```php
$wpdb->prepare( "SELECT * FROM `table` WHERE `column` = %s AND `field` = %d", 'foo', 1337 );
```
以上例子将会返回下列字符串:
```sql
SELECT * FROM `table` WHERE `column` = 'foo' AND `field` = 1337"
```

但是该函数没有并没有对传入的$query参数进行严格的过滤，如果$query参数内容或部分内容可控，就可能导致SQL注入。

prepare函数的代码如下：

```php
public function prepare( $query, $args ) {
	if ( is_null( $query ) )
		return;

	// This is not meant to be foolproof -- but it will catch obviously incorrect usage.
	if ( strpos( $query, '%' ) === false ) {
		_doing_it_wrong( 'wpdb::prepare', sprintf( __( 'The query argument of %s must have a placeholder.' ), 'wpdb::prepare()' ), '3.9.0' );
	}

	$args = func_get_args();
	array_shift( $args );
	// If args were passed as an array (as in vsprintf), move them up
	if ( isset( $args[0] ) && is_array($args[0]) )
		$args = $args[0];
	$query = str_replace( "'%s'", '%s', $query ); // in case someone mistakenly already singlequoted it
	$query = str_replace( '"%s"', '%s', $query ); // doublequote unquoting
	$query = preg_replace( '|(?<!%)%f|' , '%F', $query ); // Force floats to be locale unaware
	$query = preg_replace( '|(?<!%)%s|', "'%s'", $query ); // quote the strings, avoiding escaped strings like %%s
	array_walk( $args, array( $this, 'escape_by_ref' ) );
	return @vsprintf( $query, $args );
}
```

该函数主要做了以下几件工作：

1). 判断$args[0]是否数组，如果是则使$args=$args[0]。
2). 将$query中'%s'替换为%s。
3). 将$query中"%s"替换为%s。
4). 再将%s替换为'%s'。
5). 将$args用mysql_real_escape_string转义。
6). 返回vsprintf( $query, $args )。

经分析，该函数可能导致两个问题：

1). 逻辑漏洞

若程序中存在类似下列的代码:
```php
$query = $wpdb->prepare( 'update articles set title = %s where id = %d and uid = %d', $_GET['title'], $_GET['id'], get_current_uid());
```

按正常的业务逻辑，prepare将返回`vsprintf(  'update articles set title = %s where id = %d and uid = %d', array($_GET['title'], $_GET['id'], get_current_uid() )`的执行结果。
但是此时format后的第一个参数（$_GET['title']）我们完全可控，如果我们使第一个参数为数组，我们就可以控制用户ID，如：$_GET['title'] = array('title', 'id' ,'xxx')，此时prepare将返回`vsprintf(  'update articles set title = %s where id = %d and uid = %d', array('title', 'id' ,'xxx')`。
此时，一个越权漏洞就产生了。

2). SQL注入

若程序中存在类似下列的代码:
```php
$append = $wpdb->prepare( 'and tag = %s', $_GET['tag']);
$query = $wpdb->prepare( 'select * from articles where uid = %d and cid = %d '.$append, get_current_uid(), $_GET['cid']);
mysql_query($query);
```

我们使得`tag=%s`，则`$append="and tag = '%sa'"`。此时的`$query`将为`$wpdb->prepare( 'select * from articles where uid = %d and cid = %d and tag = \'%s\'', get_current_uid(), $_GET['cid'])`，经prepare处理后等同于`$query = vsprintf('select * from articles where uid = %d and cid = %d and tag = \'\'%s\'a\'', array(get_current_uid(), $_GET['cid']));`。
此时的%s将处于单引号之外，如果%s可控，将导致SQL注入。此时，就要用到前面1.3部分提到的**Argument numbering/swapping**，我们可以使`tag=%2$s`,但是此时不存在`%s`，经prepare函数处理后，`$query = vsprintf('select * from articles where uid = %d and cid = %d and tag = \'%2$s\'', array(get_current_uid(), $_GET['cid']));`，虽然此时的%2$s经vsprintf函数格式化后将等于`$_GET['cid']`的值，但是参数被包含在引号之内，无法导致SQL注入。

这时我们就需要用到1.3内的**字符串自动补位**。我们使`tag=%2$%s abc`，经prepare处理后`$query = vsprintf('select * from articles where uid = %d and cid = %d and tag = \'%2$\'%s\' abc\'', array(get_current_uid(), $_GET['cid']));`。此时的关键部分为`tag = '%2$'%s' abc'`，此时的`%2$'%s`为格式化标识，里面2代表第二个参数（即`$_GET['cid']`），'%表示用%填充，s表示格式化为字符串，默认的填充位数为0。

范例：
```php
echo sprintf("tag = '%1$'%s' abc'", '123');
//输出tag = '123' abc'
echo sprintf("tag = '%1$'%0s' abc'", '123');
//输出tag = '123' abc'
echo sprintf("tag = '%1$'%5s' abc'", '123');
//输出tag = '%%123' abc'
```
此时的abc将在单引号外，且用户可控，即产生了SQL注入漏洞。


## 参考链接

* Wordpress SQLi by slavco - [https://medium.com/websec/wordpress-sqli-bbb2afcc8e94](https://medium.com/websec/wordpress-sqli-bbb2afcc8e94)
