from setuptools import setup, find_packages

setup(
    name="KeyisBLogging",
    version="1.0.2",
    author="KeyisB",
    author_email="keyisb.pip@gmail.com",
    description="KeyisBLogging",
    long_description='',
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/my_library",  # Ссылка на репозиторий
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=[
        # "requests", "numpy"  # Добавьте зависимости, если есть
    ],
)
