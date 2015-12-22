from distutils.core import setup

majv = 1
minv = 0

setup(
	name = 'typetester',
	version = "%d.%d" %(majv,minv),
	description = "Python module test types",
	author = "Colin ML Burnett",
	author_email = "cmlburnett@gmail.com",
	url = "",
	packages = ['typetester'],
	package_data = {'typetester': ['typetester/__init__.py']},
	classifiers = [
		'Programming Language :: Python :: 3.4'
	]
)
