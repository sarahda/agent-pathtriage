"""AgentPathTriage.

The modules import each other flatly (`import extract_graph`) and each puts its
own directory on sys.path, which is what lets them stay runnable as scripts.
That is deliberate: the three-step pipeline is how the work is done and
debugged, and the command line sits on top of it rather than replacing it.
"""
__version__ = "0.1.0"
