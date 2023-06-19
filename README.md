# MPC-Sets-Sum
This project was developed for the Privacy Enhancing Technologies (PET) part of the Introduction to Cybersecurity course.

The goal of the project was to provide an implementation of Yao's protocol [^fn3] for performing a sum of the elements of the sets of two participants, Alice and Bob.

For the development of the project, the basic implementation proposed by Olivier Roques and Emmanuelle Risson [^fn1] was used, available at the link <https://github.com/ojroques/garbled-circuit>.

## Architecture

The project consists of the following files:
- `src/circuits/sum.json` contains the logical description of the summing circuit
- `src/main.py` implements the correct functioning of Alice and Bob. It also imple- ments the Checker, which takes care of verifying the correctness of the result
- `src/yao.py` implements:
  * Encryption and decryption functions
  * Evaluation function used by Bob to get the results of a yao circuit
  * GarbledCircuit class which generates the keys, p-bits and garbled gates of the circuit
  * GarbledGate class which generates the garbled table of a gate
- `src/ot.py` implement oblivious transfer
- `src/util.py` implements many functions related to network communications and asymmetric key generation

## Documentation
There are also two pdf files:
- `documentation.pdf` is the well detailed documentation of the project
- `SEL_report.pdf` is a SEL report, which analyzes the various applications of the MPC, deepening that of e-voting



[comment]: <> (Citations)

[^fn1]: [Roq21] Olivier Roques. Garbled circuit. [Accessed May-2023]. 2021.

[^fn3]: [Wik21b] Wikipedia contributors. Secure two-party computation — Wikipedia,
The Free Encyclopedia. [Online; accessed May-2023]. 2021.
