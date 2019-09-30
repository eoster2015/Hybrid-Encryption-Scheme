import setuptools

setuptools.setup(
    name="eoster2015_cis5371_final_project",
    version="1.0.1",
    author="Eric Oster",
    author_email="eoster2015@fau.edu",
    description="""Final project for Dr. Nojoumian's Fall 2018 section of CIS 5371. 
    Implemented a hybrid-key cryptosystem utilizing AES-256 and Blum-Goldwasser.""",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        'console_scripts': [
            'eoster2015_cis5371_final_project = eoster2015_cis5371_final_project.__main__:main'
        ]
    },
)
