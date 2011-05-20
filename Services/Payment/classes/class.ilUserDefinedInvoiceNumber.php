<?php
/* Copyright (c) 1998-2009 ILIAS open source, Extended GPL, see docs/LICENSE */

/** 
* 
* @author Nadia Ahmad <nahmad@databay.de>
* @version $Id:$
* 
* 
* @ingroup ServicesPayment
*/


class ilUserDefinedInvoiceNumber
{
	public $ud_invoice_number = 0;
	public $invoice_number_text = null;
	public $inc_start_value = 0;
	public $inc_current_value = 0;
	public $inc_reset_period = 0;
	public $last_reset = 0;

	// SETTER/GETTER
	
	/* enable user-defined invoice number -> 1 
	 * disable for using standard ilias invoice number -> 0
	 *
	 */
	public function setUDInvoiceNumberActive($a_ud_invoice_number)
	{
		$this->ud_invoice_number = $a_ud_invoice_number;
	}
	public function getUDInvoiceNumberActive()
	{
		return $this->ud_invoice_number;
	}

	public function setInvoiceNumberText($a_invoice_number_text)
	{
		$this->invoice_number_text = $a_invoice_number_text;
	}
	public function getInvoiceNumberText()
	{
		return $this->invoice_number_text;
	}

	public function setIncStartValue($a_inc_start_value)
	{
		$this->inc_start_value = $a_inc_start_value;
	}
	public function getIncStartValue()
	{
		return $this->inc_start_value;
	}

	public function setIncCurrentValue($a_inc_current_value)
	{
		$this->inc_current_value = $a_inc_current_value;
	}
	public function getIncCurrentValue()
	{
		return $this->inc_current_value;
	}

	/*
	 *  @param integer $a_inc_reset_period (1=yearly, 2=monthly)
	 */
	public function setIncResetPeriod($a_inc_reset_period)
	{
		$this->inc_reset_period = $a_inc_reset_period;
	}
	public function getIncResetPeriod()
	{
		return $this->inc_reset_period;
	}

	/*
	 * @param integer timestamp
	 */
	public function setIncLastReset($a_timestamp)
	{
		$this->inc_last_reset = $a_timestamp;
	}

	public function getIncLastReset()
	{
		return $this->inc_last_reset;
	}

	public function __construct()
	{
		$this->read();
	}

	public function read()
	{
		global $ilDB;

		$res = $ilDB->queryF('SELECT * FROM payment_settings WHERE settings_id = %s',
				array('integer'), array(1));

		while($row = $ilDB->fetchAssoc($res))
		{
			$this->ud_invoice_number = $row['ud_invoice_number'];
			$this->invoice_number_text = $row['invoice_number_text'];
			$this->inc_start_value = $row['inc_start_value'];
			$this->inc_current_value = $row['inc_current_value'];
			$this->inc_reset_period = $row['inc_reset_period'];
			$this->inc_last_reset = $row['inc_last_reset'];
		}	
	}

	public function update()
	{
		global $ilDB;

		$res = $ilDB->update('payment_settings',
				array('ud_invoice_number' => array('integer', $this->getUDInvoiceNumberActive()),
					'invoice_number_text' => array('text', $this->getInvoiceNumberText()),
					'inc_start_value'	  => array('integer', $this->getIncStartValue()),
					'inc_reset_period'  => array('integer', $this->getIncResetPeriod())
					),
				array('settings_id' => array('integer', 1)));
	}


	public static function _nextIncCurrentValue()
	{
		global $ilDB;

		$res = $ilDB->queryf('SELECT inc_current_value FROM payment_settings WHERE settings_id = %s',
				array('integer'), array(1));

		$row = $ilDB->fetchAssoc($res);
		$cur_id = (int)$row['inc_current_value'];
		$next_id = ++$cur_id;

		$upd = $ilDB->update('payment_settings', 
				array('inc_current_value' => array('integer', $next_id)),
				array('settings_id' => array('integer', 1)));

		return $next_id;

	}
	/**
	 * @param  integer $a_value
	 */
	public static function _setIncCurrentValue($a_value)
	{
		global $ilDB;

		$res = $ilDB->update('payment_settings',
				array('inc_current_value' => array('integer', $a_value)),
				array('settings_id' => array('integer', 1)));

	}
	public static function _getIncCurrentValue()
	{
		global $ilDB;

		$res = $ilDB->queryf('SELECT inc_current_value FROM payment_settings
			WHERE settings_id = %s',
			array('integer'), array(1));

		$row = $ilDB->fetchAssoc($res);

		return $row['inc_current_value'];
	}
	public static function _getResetPeriod()
	{
		global $ilDB;

		$res = $ilDB->queryf('SELECT inc_reset_period FROM payment_settings
			WHERE settings_id = %s',
			array('integer'), array(1));

		$row = $ilDB->fetchAssoc($res);

		return $row['inc_reset_period'];
	}

	/*
	 *
	 *  @return boolean
	 */
	public static function _isUDInvoiceNumberActive()
	{
		global $ilDB;

		if(!IS_PAYMENT_ENABLED) return false;

		$res = $ilDB->queryf('SELECT ud_invoice_number FROM payment_settings
			WHERE settings_id = %s',
			array('integer'), array(1));

		$row = $ilDB->fetchAssoc($res);
		if($row['ud_invoice_number'] == 1)
			return true;
		else
			return false;
	}

// CRON CHECK
	public function cronCheck()
	{
		global $ilDB;

		$last_reset = $this->getIncLastReset();
		$last_month = date('n', $last_reset);
		$last_year = date('Y', $last_reset);

		$now = time();
		$now_month = date('n', $now);
		$now_year = date('Y', $now);

		$reset_type = $this->getIncResetPeriod();

		switch($reset_type)
		{
			case '1': #yearly
				if($last_year < $now_year)
				{
					$reset = true;
				}
				break;
			case '2': #monthly
				if(($last_month < $now_month) || ($last_month > $now_month && $last_year < $now_year) )
				{
					$reset = true;
				}
				break;
			default:
				$reset = false;
				break;
		}

		if($reset == true)
		{
			$this->setIncCurrentValue($this->getIncStartValue());
			$this->setIncLastReset(mktime(0, 0, 0, $now_month, 1, $now_year));
			$this->__updateCron();
		}
	}

	private function __updateCron()
	{
		global $ilDB;

		$res = $ilDB->update('payment_settings',
		array(	'inc_current_value'  => array('integer', $this->getIncCurrentValue()),
				'inc_last_reset'	=> array('integer', $this->getIncLastReset())),
		array('settings_id' => array('integer', 1)));
	}
}
?>