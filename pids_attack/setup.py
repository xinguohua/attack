from setuptools import setup, find_packages

setup(
    name="pids_attack",
    version="0.1.0",
    description="Black-box command-level adversarial attack on Provenance-based IDS",
    packages=find_packages(
        include=[
            "attack*",
            "cmd_graph*",
            "detection*",
            "experiments*",
            "range*",
            "scenarios*",
            "shared*",
        ]
    ),
    python_requires=">=3.9",
    install_requires=[
        "numpy>=1.24",
        "scikit-learn>=1.3",
        "pyyaml>=6.0",
    ],
    extras_require={
        "pidsmaker": ["psycopg2-binary>=2.9"],
        "test": ["pytest>=7.4"],
    },
)
