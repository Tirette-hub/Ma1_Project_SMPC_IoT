#!/bin/bash/python3
#encoding: utf-8

def get_len(val):
		"""
		Get the minimum bytes number required to represent an integer value.

		Arguments:
			val (int): The value to use.

		Returns:
			The minimum number of bytes required.
		"""
		i = 1
		while True:
			if val < 2**(8*i):
				return i
			i += 1