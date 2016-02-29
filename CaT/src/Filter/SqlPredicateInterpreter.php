<?php

/* Copyright (c) 2016 Denis Köpfer, Extended GPL, see docs/LICENSE */

namespace CaT\Filter;

/**
 * Interpreter to check the predicate on a dictionary.
 */
class DictionaryPredicateInterpreter {

	const IS_STR = 1;
	const IS_INT = 2;
	const IS_DATE = 3;
	const IS_FIELD = 4;

	protected $db;

	public function __constructor($db) {
		$this->db = $db;
	}

	/**
	 * Check a predicate on a dictonary.
	 * 
	 * @return	bool
	 */
	public function interpret( \CaT\Filter\Predicates\Predicate $p) {
		if ($p instanceof \CaT\Filter\Predicates\PredicateTrue) {
			return 'TRUE ';
		}

		if ($p instanceof \CaT\Filter\Predicates\PredicateNot) {
			return 'NOT ('.$this->interpret($p->sub()).')';
		}

		if ($p instanceof \CaT\Filter\Predicates\PredicateAny) {
			$parts = array();
			$predicates = $p->subs();
			foreach ($predicates as $predicate) {
				$parts[] = '('.$this->interpret($predicate).') ';
			}

			return implode('OR ',$parts);
		}

		if ($p instanceof \CaT\Filter\Predicates\PredicateAll) {
			$parts = array();
			$predicates = $p->subs();
			foreach ($predicates as $predicate) {
				$parts[] = '('.$this->interpret($predicate).') ';
			}

			return implode('AND ',$parts);
		}

		if($p instanceof \CaT\Filter\Predicates\PredicateIn) {
			$value = $p->getValue();
			$return .= $this->quoteFieldOrValue($value).' IN(';
			$list = $p->getList()->values();
			$in = array();
			foreach($list as $list_el) {
				$in[] = $this->quoteFieldOrValue($list_el);
			}
			return $return.implode(',',$in).')';
		}

		if ($p instanceof \CaT\Filter\Predicates\PredicateComparison) {
			$left = $p->left();
			$right = $p->right();
			$left_type = $this->varType($left);
			$left_quote = $this->quoteFieldOrValue($left);
			$right_type = $this->varType($right);
			$right_quote = $this->quoteFieldOrValue($right);

			if($right_type !== $left_type && $right_type !== self::IS_FIELD && $left_type !== self::IS_FIELD  ) {
				throw new \InvalidArgumentException("SqlPredicateInterpreter::interpret :"
					." comparing different field types");
			}
			if($p instanceof  \CaT\Filter\Predicates\PredicateEq) {
				return $left.' = '.$right.' ';
			}
			if($p instanceof  \CaT\Filter\Predicates\PredicateNeq) {
				return $left.' != '.$right.' ';
			}
			if($p instanceof  \CaT\Filter\Predicates\PredicateLt) {
				return $left.' < '.$right.' ';
			}
		}
		throw new \InvalidArgumentException("SqlPredicateInterpreter::interpret : possibly unknown prediacte type");
	}

	protected function quoteFieldOrValue($var) {
		if( $var instanceof \CaT\Filter\Predicates\ValueStr) {
			return $this->db->quote($var->value,'text');
		}
		if( $var instanceof \CaT\Filter\Predicates\ValueInt) {
			return $this->db->quote($var->value,'integer');
		}
		if( $var instanceof \CaT\Filter\Predicates\ValueDate) {
			return $this->db->quote($var->value->format('Y-m-d H:i'),'date');
		}
		if( $var instanceof \CaT\Filter\Predicates\Field) {
			return $this->quoteField($var);
		}
		throw new \InvalidArgumentException("SqlPredicateInterpreter::varType : invalid var type");
	}

	protected function quoteField(\CaT\Filter\Predicates\Field $field) {
		$field_name = $field->name();
		if(0 === preg_match('#^([a-zA-Z0-9_]+.)?[a-zA-Z0-9_]+$#', $field_name)) {
			throw new \InvalidArgumentException("SqlPredicateInterpreter::quoteField : field title invalid");
		}
		implode('.',array_walk(explode('.',$field_name), function (&$name_part) { $name_part = '`'.$name_part.'`';} ));
		return $field_name;
	}

	protected function varType($var) {
		if( $var instanceof \CaT\Filter\Predicates\ValueStr) {
			return self::IS_STR;
		}
		if( $var instanceof \CaT\Filter\Predicates\ValueInt) {
			return self::IS_INT;
		}
		if( $var instanceof \CaT\Filter\Predicates\ValueDate) {
			return self::IS_DATE;
		}
			if( $var instanceof \CaT\Filter\Predicates\Field) {
			return self::IS_FIELD;
		}
		throw new \InvalidArgumentException("SqlPredicateInterpreter::varType : invalid var type");
	}
}