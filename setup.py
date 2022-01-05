import setuptools


print(setuptools.find_packages())

setuptools.setup(
    name='toolbox',
    version='0.0.10',
    author='Ibrahim Albaba',
    author_email='ibrahim@uvita-digital.com',
    description='CLS Stream Toolbox',
    # long_description="This toolbox is the coolest thing to ever happen to you",
    # long_description_content_type="text/markdown",
    url='https://github.com/ibrahim-uvita/toolbox',
    project_urls = {
        "Bug Tracker": "https://github.com/ibrahim-uvita/toolbox/issues"
    },
    license='MIT',
    packages=setuptools.find_packages(),
    install_requires=['sqlalchemy'],
)

