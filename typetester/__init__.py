"""
typetester -- module for testing if objects are convertable to the given type.

Helper test methods that test if the arguments are convertable to the desired type.
This does not test if the objects are of the type (e.g., isinstance), but convertable to that type.
The only way to test this is by calling the constructor on the object.

IsFoo(o) tests if the single object is convertable to type Foo.
IsFooAll(*objects) tests if the multiple objects are *ALL* convertable to type Foo.
IsFooAny(*objects) tests if at least one of the multiple objects is convertable to type Foo.
IsFooCustom(tester, *objects) tests all of the objects and passes the result list to the tester for custom testing.

Note that the builtin methods all() and any() short-circuit and so do IsFooAll and IsFooAny.
IsFooCustom is not short-circuited as all are tested.

Also note that every type should be convertable to str() and bool() and thus neither of these types are provided.

One last note, this catches *any* exception thrown during creation and results in False.

Motivation: try-except blocks are incompatible with if-elif-else statements, which makes code significantly uglier and necessitates an intermediate variable

	try:
		v = int(somevalue)
		isint = True
	except:
		v = None
		isint = False

	if isint:
		doIfTrue(v)
	else:
		doIfFalse()

It is possible to include the logic within the try-except block

	try:
		v = int(somevalue)
		doIfTrue(v)
	except:
		doIfFalse()

But these two blocks are *NOT* equivalent for any and all code you can put in doIfTrue and doIfFalse.
You don't understand Python's exception system if you don't know why...

The alternative with typetester:

	import typetester

	if IsInt(somevalue):
		doIfTrue( int(somevalue) )
	else:
		doIfFalse()

The latter approach, however, requires calling int() twice: once for IsInt() and once again later to get the integer value of @somevalue.

So, which is best for you:
	* Do you need the answer in an if-elif-else block?
	* Do you care if the exception space overlaps between testing and using the value?
	* Do you care about using temporary variables?
	* Do you mind spending extra time to convert twice?
"""

__all__ = ['TypeTest']
__all__.extend(['IsInt','IsIntAll','IsIntAny','IsIntCustom'])
__all__.extend(['IsComplex','IsComplexAll','IsComplexAny','IsComplexCustom'])
__all__.extend(['IsFloat','IsFloatAll','IsFloatAny','IsFloatCustom'])
__all__.extend(['IsDecimal','IsDecimalAll','IsDecimalAny','IsDecimalCustom'])
__all__.extend(['IsFraction','IsFractionAll','IsFractionAny','IsFractionCustom'])
__all__.extend(['IsUUID','IsUUIDAll','IsUUIDAny','IsUUIDCustom'])
__all__.extend(['IsIP','IsIPAll','IsIPAny','IsIPCustom'])
__all__.extend(['IsIPv4','IsIPv4All','IsIPv4Any','IsIPv4Custom'])
__all__.extend(['IsIPv6','IsIPv6All','IsIPv6Any','IsIPv6Custom'])

import decimal, fractions, uuid, ipaddress

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# Int

def IsInt(o):
	"""
	Test if the argument is convertable to an int() or not.
	"""
	return TypeTest(int, all, o)

def IsIntAll(*objects):
	"""
	Test if all the arguments are convertable to an int() or not.
	"""
	return TypeTest(int, all, *objects)

def IsIntAny(*objects):
	"""
	Test if any of the arguments is convertable to an int() or not.
	"""
	return TypeTest(int, any, *objects)

def IsIntCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an int() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(int, tester, *objects)

def AsIntDefault(o, default):
	"""
	Get object as int, or the default if not convertable to an int.
	"""
	return AsDefault(int, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# Complex

def IsComplex(o):
	"""
	Test if the argument is convertable to an complex() or not.
	"""
	return TypeTest(complex, all, o)

def IsComplexAll(*objects):
	"""
	Test if all the arguments are convertable to an complex() or not.
	"""
	return TypeTest(complex, all, *objects)

def IsComplexAny(*objects):
	"""
	Test if any of the arguments is convertable to an complex() or not.
	"""
	return TypeTest(complex, any, *objects)

def IsComplexCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an complex() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(complex, tester, *objects)

def AsComplexDefault(o, default):
	"""
	Get object as complex, or the default if not convertable to an complex.
	"""
	return AsDefault(complex, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# Float

def IsFloat(o):
	"""
	Test if the argument is convertable to an float() or not.
	"""
	return TypeTest(float, all, o)

def IsFloatAll(*objects):
	"""
	Test if all the arguments are convertable to an float() or not.
	"""
	return TypeTest(float, all, *objects)

def IsFloatAny(*objects):
	"""
	Test if any of the arguments is convertable to an float() or not.
	"""
	return TypeTest(float, any, *objects)

def IsFloatCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an float() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(float, tester, *objects)

def AsFloatDefault(o, default):
	"""
	Get object as float, or the default if not convertable to an float.
	"""
	return AsDefault(float, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# Decimal

def IsDecimal(o):
	"""
	Test if the argument is convertable to an decimal.Decimal() or not.
	"""
	return TypeTest(decimal.Decimal, all, o)

def IsDecimalAll(*objects):
	"""
	Test if all the arguments are convertable to an decimal.Decimal() or not.
	"""
	return TypeTest(decimal.Decimal, all, *objects)

def IsDecimalAny(*objects):
	"""
	Test if any of the arguments is convertable to an decimal.Decimal() or not.
	"""
	return TypeTest(decimal.Decimal, any, *objects)

def IsDecimalCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an decimal.Decimal() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(decimal.Decimal, tester, *objects)

def AsDecimalDefault(o, default):
	"""
	Get object as decimal.Decimal, or the default if not convertable to an decimal.Decimal.
	"""
	return AsDefault(decimal.Decimal, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# Fraction

def IsFraction(o):
	"""
	Test if the argument is convertable to an fractions.Fraction() or not.
	"""
	return TypeTest(fractions.Fraction, all, o)

def IsFractionAll(*objects):
	"""
	Test if all the arguments are convertable to an fractions.Fraction() or not.
	"""
	return TypeTest(fractions.Fraction, all, *objects)

def IsFractionAny(*objects):
	"""
	Test if any of the arguments is convertable to an fractions.Fraction() or not.
	"""
	return TypeTest(fractions.Fraction, any, *objects)

def IsFractionCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an fractions.Fraction() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(fractions.Fraction, tester, *objects)

def AsFractionDefault(o, default):
	"""
	Get object as fractions.Fraction, or the default if not convertable to an fractions.Fraction.
	"""
	return AsDefault(fractions.Fraction, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# UUID

def IsUUID(o):
	"""
	Test if the argument is convertable to an uuid.UUID() or not.
	"""
	return TypeTest(uuid.UUID, all, o)

def IsUUIDAll(*objects):
	"""
	Test if all the arguments are convertable to an uuid.UUID() or not.
	"""
	return TypeTest(uuid.UUID, all, *objects)

def IsUUIDAny(*objects):
	"""
	Test if any of the arguments is convertable to an uuid.UUID() or not.
	"""
	return TypeTest(uuid.UUID, any, *objects)

def IsUUIDCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an uuid.UUID() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(uuid.UUID, tester, *objects)

def AsUUIDDefault(o, default):
	"""
	Get object as uuid.UUID, or the default if not convertable to an uuid.UUID.
	"""
	return AsDefault(uuid.UUID, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# IP address (either IPv4 or IPv6

def IsIP(o):
	"""
	Test if the argument is convertable to an ipaddress.IPv4Address() or ipadddress.IPv6Address() or not.
	"""
	return TypeTest(ipaddress.ip_address, all, o)

def IsIPAll(*objects):
	"""
	Test if all the arguments are convertable to an ipaddress.IPv4Address() or ipadddress.IPv6Address() or not.
	"""
	return TypeTest(ipaddress.ip_address, all, *objects)

def IsIPAny(*objects):
	"""
	Test if any of the arguments is convertable to an ipaddress.IPv4Address() or ipadddress.IPv6Address() or not.
	"""
	return TypeTest(ipaddress.ip_address, any, *objects)

def IsIPCustom(tester, *objects):
	"""
	Test if the arguments is convertable to an ipaddress.IPv4Address() or ipadddress.IPv6Address() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(ipaddress.ip_address, tester, *objects)

def AsIPDefault(o, default):
	"""
	Get object as ipaddress.IPv4Address() or ipaddress.IPv6Address(), or the default if not convertable to an ipaddress.IPv4Address() or ipaddress.IPv6Address().
	"""
	return AsDefault(ipaddress.ip_address, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# IPv4Address

def IsIPv4(o):
	"""
	Test if the argument is convertable to an ipaddress.IPv4Address() or not.
	"""
	return TypeTest(ipaddress.IPv4Address, all, o)

def IsIPv4All(*objects):
	"""
	Test if all the arguments are convertable to an ipaddress.IPv4Address() or not.
	"""
	return TypeTest(ipaddress.IPv4Address, all, *objects)

def IsIPv4Any(*objects):
	"""
	Test if any of the arguments is convertable to an ipaddress.IPv4Address() or not.
	"""
	return TypeTest(ipaddress.IPv4Address, any, *objects)

def IsIPv4Custom(tester, *objects):
	"""
	Test if the arguments is convertable to an ipaddress.IPv4Address() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(ipaddress.IPv4Address, tester, *objects)

def AsIPv4Default(o, default):
	"""
	Get object as ipaddress.IPv4Address, or the default if not convertable to an ipaddress.IPv4Address.
	"""
	return AsDefault(ipaddress.IPv4Address, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------
# IPv6Address

def IsIPv6(o):
	"""
	Test if the argument is convertable to an ipaddress.IPv6Address() or not.
	"""
	return TypeTest(ipaddress.IPv6Address, all, o)

def IsIPv6All(*objects):
	"""
	Test if all the arguments are convertable to an ipaddress.IPv6Address() or not.
	"""
	return TypeTest(ipaddress.IPv6Address, all, *objects)

def IsIPv6Any(*objects):
	"""
	Test if any of the arguments is convertable to an ipaddress.IPv6Address() or not.
	"""
	return TypeTest(ipaddress.IPv6Address, any, *objects)

def IsIPv6Custom(tester, *objects):
	"""
	Test if the arguments is convertable to an ipaddress.IPv6Address() and those results pass the custom tester @tester (which takes a single argument that is a list of True or False, one per argument, and in the same order).
	"""
	return TypeTest(ipaddress.IPv6Address, tester, *objects)

def AsIPv6Default(o, default):
	"""
	Get object as ipaddress.IPv6Address, or the default if not convertable to an ipaddress.IPv6Address.
	"""
	return AsDefault(ipaddress.IPv6Address, o, default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------

def TypeTest(typ, listtest, *objects):
	"""
	Test if @o is convertable to type @typ.
	This merely calls the constructor as the test.
	"""

	if not callable(listtest): raise TypeError("Expected a callable function as the as the tester method, got type '%s' which is not callable" % type(listtest))

	if listtest == all:
		try:
			# All must be converted for True to be returned
			[typ(o) for o in objects]
			return True
		except:
			return False

	elif listtest == any:
		for o in objects:
			try:
				# Only the first successful is needed for True to be returned
				typ(o)
				return True
			except:
				pass

		return False

	else:
		ret = []
		for o in objects:
			try:
				typ(o)
				ret.append(True)
			except:
				ret.append(False)

		# Force the function to return a bool
		return bool(listtest(ret))

def AsDefault(typ, o, default):
	"""
	Get object as type @typ, or the default if not convertable to an int.
	"""
	# Ensure that default is convertable too
	try:
		typ(default)
	except Exception as e:
		raise TypeError("Default must be convertable to the intended type (%s), but it is not (%s)" % (typ, type(default))) from e

	try:
		return typ(o)
	except:
		return typ(default)

# --------------------------------------------------------------------------------
# --------------------------------------------------------------------------------

def test():
	# NB: this is not a test of int() as correct or not, only that these functions work as indicated
	# thus it is not necessary to exhaustively test every method for all types

	assert(IsInt('1'))
	assert(not IsInt('f'))
	assert(IsIntAll('1', '2', '3'))
	assert(not IsIntAll('1', 'x', '3'))
	assert(IsIntAny('1', 'x', 'p'))
	assert(IsIntAny('x', '1', 'p'))
	assert(not IsIntAny('a', 'x', 'p'))

	def FTF(x):
		return all([not x[0], x[1], not x[2]])

	assert(IsIntCustom(FTF, 'x', '1', 'y'))
	assert(not IsIntCustom(FTF, '1', '1', 'y'))
	assert(not IsIntCustom(FTF, 'x', '1', '1'))
	assert(not IsIntCustom(FTF, 'x', 'b', 'y'))

	assert(IsComplex('(8+6j)'))
	assert(IsComplex('j'))
	assert(IsComplexAll('(8+6j)', '(10-4j)'))
	assert(IsComplexAny('(8+6j)', 'j'))
	assert(IsComplexCustom(FTF, 'x', '(8+6j)', 'p'))

	assert(IsFloat('2.4'))
	assert(IsFloatAll('2.4', '10'))
	assert(IsFloatAny('2.4', 'x', 'j'))
	assert(IsFloatCustom(FTF, 'x', '2.4', 'j'))

	assert(IsDecimal('2.4'))
	assert(IsDecimalAll('2.4', '10'))
	assert(IsDecimalAny('2.4', 'x', 'j'))
	assert(IsDecimalCustom(FTF, 'x', '2.4', 'j'))

	assert(IsFraction('3/7'))
	assert(IsFractionAll('3/7', '1/3'))
	assert(IsFractionAny('3/7', 'x', 'j'))
	assert(IsFractionCustom(FTF, 'j', '3/7', 'x'))

	assert(IsUUID('{12345678-1234-5678-1234-567812345678}'))
	assert(IsUUIDAll('{12345678-1234-5678-1234-567812345678}', '12345678123456781234567812345678'))
	assert(IsUUIDAny('3/7', '{12345678-1234-5678-1234-567812345678}', 'j'))
	assert(IsUUIDCustom(FTF, '3/7', '{12345678-1234-5678-1234-567812345678}', 'j'))

	assert(IsIP('2.4.6.8'))
	assert(IsIPAll('2.4.6.8', '2001:db8::'))
	assert(IsIPAny('2.4.6.8', 'x', 'j'))
	assert(IsIPCustom(FTF, '3/7', '2.4.6.8', 'j'))

	assert(IsIPv4('2.4.6.8'))
	assert(IsIPv4All('2.4.6.8', '0.0.0.0'))
	assert(IsIPv4Any('2.4.6.8', 'x', 'j'))
	assert(IsIPv4Custom(FTF, '3/7', '2.4.6.8', 'j'))

	assert(IsIPv6('2001:db8::'))
	assert(IsIPv6All('2001:db8::', '::1'))
	assert(IsIPv6Any('::1', 'x', 'j'))
	assert(IsIPv6Custom(FTF, '3/7', '2001:db8::', 'j'))



	assert(AsIntDefault('2', 1) == 2)
	assert(AsIntDefault('q', 1) == 1)

	assert(AsComplexDefault('(6+8j)', 1.0) == complex(6,8))
	assert(AsComplexDefault('q', 1.0) == 1.0)

	assert(AsFloatDefault('8.5', 1.0) == 8.5)
	assert(AsFloatDefault('q', 1.0) == float(1.0))

	assert(AsDecimalDefault('8.5', 1.0) == 8.5)
	assert(AsDecimalDefault('q', 1.0) == decimal.Decimal(1.0))

	assert(AsUUIDDefault('12345678123456781234567812345678', '92345678123456781234567812345679') == uuid.UUID('12345678123456781234567812345678'))
	assert(AsUUIDDefault('q', '12345678123456781234567812345678') == uuid.UUID('12345678123456781234567812345678'))

	assert(AsIPDefault('0.0.0.0', '1.2.3.4') == ipaddress.IPv4Address('0.0.0.0'))
	assert(AsIPDefault('q', '1.2.3.4') == ipaddress.IPv4Address('1.2.3.4'))

	assert(AsIPv4Default('0.0.0.0', '1.2.3.4') == ipaddress.IPv4Address('0.0.0.0'))
	assert(AsIPv4Default('q', '1.2.3.4') == ipaddress.IPv4Address('1.2.3.4'))

	assert(AsIPv6Default('::1', '2001:db8::') == ipaddress.IPv6Address('::1'))
	assert(AsIPv6Default('q', '2001:db8::') == ipaddress.IPv6Address('2001:db8::'))


	try:
		AsIntDefault('2', 'q')
		assert("Should not reach this point, did not check default as the type")
	except:
		pass

	print("All pass")


if __name__ == "__main__":
	test()

