<?php
// no direct access
defined('_JEXEC') or die('Restricted access');

jimport('joomla.plugin.plugin');

class plgSystemDenyReferer extends JPlugin
{
	protected $referer = null;

	public function __construct(&$subject, $config)
	{
		$this->referer = JRequest::getString('HTTP_REFERER', null, 'server');
		parent::__construct($subject, $config);
	}

	public function onAfterInitialise()
	{
		$application =& JFactory::getApplication();

		if (
			JDEBUG
			|| ((int) $this->params->get('check_admin') == 0 && $application->isAdmin())
			|| empty($this->referer)
		){
			return;
		}

		$domains = explode("\n", str_replace("\r", '', trim($this->params->get('domains'))));
		$urls    = explode("\n", str_replace("\r", '', trim($this->params->get('urls'))));
		$host    = parse_url($this->referer, PHP_URL_HOST);

		if (
			$this->match($this->referer, $urls)
			|| $this->match($host, $domains)
		){
			$this->deny();
		}
	}

	protected function match($needle, $haystacks)
	{
		foreach ((array) $haystacks as $haystack)
		{
			if (strpos($haystack, '[regex]') === false)
			{
				$haystack = str_replace(array('*', '?'), array('.*', '.'), $haystack);
			}
			if ( ! empty($haystack) && preg_match('^'.$haystack.'^i', $needle))
			{
				return true;
			}
		}
		return false;
	}

	protected function deny()
	{
		$application =& JFactory::getApplication();
		if (headers_sent())
		{
			if ($this->params->get('deny_method') == '1')
			{
				// deny_method == redirect
				echo '<meta http-equiv="refresh" content="0;URL=\''.$this->referer.'\'">';
				echo '<script type="text/javascript">window.location.href="'.$this->referer.'";</script>';
			}
			$application->close('<h1>Forbidden</h1>');
		}
		header("HTTP/1.0 403 Forbidden");
		if ($this->params->get('deny_method') == '1')
		{
			// deny_method == redirect
			header('Location: '.$this->referer);
		}
		$application->close();
	}

}
