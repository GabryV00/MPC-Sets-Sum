#!/usr/bin/env python3
import os
import argparse
import ot
import util
import yao
from abc import ABC, abstractmethod

class YaoGarbler(ABC):
    """An abstract class for Yao garblers (e.g. Alice)."""
    def __init__(self, circuits):
        circuits = util.parse_json(circuits)
        self.name = circuits["name"]
        self.circuits = []

        for circuit in circuits["circuits"]:
            garbled_circuit = yao.GarbledCircuit(circuit)
            pbits = garbled_circuit.get_pbits()
            entry = {
                "circuit": circuit,
                "garbled_circuit": garbled_circuit,
                "garbled_tables": garbled_circuit.get_garbled_tables(),
                "keys": garbled_circuit.get_keys(),
                "pbits": pbits,
                "pbits_out": {w: pbits[w]
                              for w in circuit["out"]},
            }
            self.circuits.append(entry)

    @abstractmethod
    def start(self):
        pass


class Alice(YaoGarbler):
    """Alice is the creator of the Yao circuit.

    Alice creates a Yao circuit and sends it to the evaluator along with her
    encrypted inputs. Alice will finally print the truth table of the circuit
    for all combination of Alice-Bob inputs.

    Alice does not know Bob's inputs but for the purpose
    of printing the truth table only, Alice assumes that Bob's inputs follow
    a specific order.

    Attributes:
        circuits: the JSON file containing circuits
        set: the set of values of Alice
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
        print_mode: Optional; Possible values:
                                    circuit: prints the truth table
                                    table: prints the tables sent by Alice to Bob
                    Default: circuit
    """
    def __init__(self, circuits, set, oblivious_transfer=True, print_mode="circuit"):
        super().__init__(circuits)
        self.socket = util.GarblerSocket()
        self._print_mode = print_mode
        self.modes = {
            "circuit": self.print,
            "table": self._print_tables,
        }
        self.set = set
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)
        self.checker = Checker()

    def interpret_result(self, str_results):
        for str_result in str_results:
            result = str_result.replace(' ', "")
            result = int(result[::-1], 2)

            #Printing the expected output
            exp_output = self.checker.get_exp_output()
            print(exp_output)

            #Printing the output
            str_output = f"[OUTPUT] The sum of the elements is: {result}"
            print(str_output)
            create_fileset("output", [result])

            #Checking the correctness of the result
            get_res = self.checker.get_result(result)
            print(get_res)
            #Sending all output to Bob
            self.socket.send(exp_output + "\n" + str_output + "\n" + get_res)

    def start(self):
        """Start Yao protocol."""
        for circuit in self.circuits:
            to_send = {
                "circuit": circuit["circuit"],
                "garbled_tables": circuit["garbled_tables"],
                "pbits_out": circuit["pbits_out"],
            }
            if self._print_mode == "circuit":
                self.socket.send_wait(to_send)
            self.modes[self._print_mode](circuit)

    def _print_tables(self, entry):
        """Print garbled tables."""
        entry["garbled_circuit"].print_garbled_tables()

    def print(self, entry):
        """Print circuit evaluation for all Bob and Alice inputs.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits, keys = entry["circuit"], entry["pbits"], entry["keys"]
        outputs = circuit["out"]
        a_wires = circuit.get("alice", [])  # Alice's wires
        a_inputs = {}  # map from Alice's wires to (key, encr_bit) inputs
        b_wires = circuit.get("bob", [])  # Bob's wires
        b_keys = {  # map from Bob's wires to a pair (key, encr_bit)
            w: self._get_encr_bits(self, pbits[w], key0, key1)
            for w, (key0, key1) in keys.items() if w in b_wires
        }

        print(f"\n======== {circuit['id']} ========")

        str_results = []

        bits_a = [int(i) for i in bin(sum(self.set))[2:][::-1]]  # Alice's inputs
        if len(bits_a) < 8:
            for i in range(8 - len(bits_a)):
                bits_a.append(0)

        # Map Alice's wires to (key, encr_bit)
        for i in range(len(a_wires)):
            a_inputs[a_wires[i]] = (keys[a_wires[i]][bits_a[i]], pbits[a_wires[i]] ^ bits_a[i])

        # Send Alice's encrypted inputs and keys to Bob
        result = self.ot.get_result(a_inputs, b_keys)

        # Format output
        str_bits_a = [str(i) for i in bits_a]
        str_bits_a = ' '.join(str_bits_a[:len(a_wires)])
        str_result = ' '.join([str(result[w]) for w in outputs])
        str_results.append(str_result)
        print(f"\nAlice{a_wires} = {str_bits_a}"
              f"\nOutputs{outputs} = {str_result}")

        self.interpret_result(str_results)
        print()

    @staticmethod
    def _get_encr_bits(self, pbit, key0, key1):
        return ((key0, 0 ^ pbit), (key1, 1 ^ pbit))


class Bob:
    """Bob is the receiver and evaluator of the Yao circuit.

    Bob receives the Yao circuit from Alice, computes the results and sends
    them back.

    Args:
        set: the set of value of the other party (Alice)
        oblivious_transfer: Optional; enable the Oblivious Transfer protocol
            (True by default).
    """
    def __init__(self, set, oblivious_transfer=True):
        self.socket = util.EvaluatorSocket()
        self.ot = ot.ObliviousTransfer(self.socket, enabled=oblivious_transfer)
        self.set = set

    def update_set(self, new_set):
        self.set = new_set

    def listen(self):
        """Start listening for Alice messages."""

        try:
            for entry in self.socket.poll_socket():
                self.socket.send(True)
                self.send_evaluation(entry)
                print(self.socket.receive() + "\n")
                break

        except KeyboardInterrupt:
            print("Connection closed")

    def send_evaluation(self, entry):
        """Evaluate yao circuit for all Bob and Alice's inputs and
        send back the results.

        Args:
            entry: A dict representing the circuit to evaluate.
        """
        circuit, pbits_out = entry["circuit"], entry["pbits_out"]
        garbled_tables = entry["garbled_tables"]
        b_wires = circuit.get("bob", [])  # list of Bob's wires

        print(f"\n======= Received {circuit['id']} =======")

        bits_b = [int(i) for i in bin(sum(self.set))[2:][::-1]]  # Bob's inputs
        if len(bits_b) < 8:
            for i in range(8 - len(bits_b)):
                bits_b.append(0)

        # Create dict mapping each wire of Bob to Bob's input
        b_inputs_clear = {
            b_wires[i]: bits_b[i]
            for i in range(len(b_wires))
        }

        # Evaluate and send result to Alice
        self.ot.send_result(circuit, garbled_tables, pbits_out, b_inputs_clear)


class Checker:
    """
    This class is a checker, which will be used by Alice to verify the result.
    PAY ATTENTION: in real use, this class would not exist
    """
    input_alice = None
    input_bob = None
    expected_output = None

    def __init__(self):
        file_path = "./input_sets/alice_set.txt" if os.path.dirname(__file__) is None or os.path.dirname(__file__) == "" else os.path.dirname(__file__) + "/input_sets/alice_set.txt"
        file_path = file_path.replace(".txt", "")
        file_path = file_path + '.txt'

        with open(file_path, 'r') as setfile:
            self.input_alice = [int(x) for x in next(setfile).split()]
            setfile.close()

        file_path = file_path.replace("alice", "bob")
        with open(file_path, 'r') as setfile:
            self.input_bob = [int(x) for x in next(setfile).split()]
            setfile.close()

    def get_exp_output(self):
        self.expected_output = sum(self.input_alice)+sum(self.input_bob)
        return f"\n[EXPECTED OUTPUT] The sum of the elements from Alice and Bob should be: {self.expected_output}"

    def get_result(self, out):
        if out == self.expected_output:
            return "[CORRECT] The yao's output is equal to the one computed in normal way."
        else:
            return "[ERROR] The output is not equal to the one computed in normal way"


def create_fileset(party, party_set):
    """
    The function saves the set of numbers received as param into a file placed in the specific directory.
    It is also used to save the result of the computation.

    :param party: alice, bob, output
    :param party_set: the related set of integers
    """

    if party == "alice":
        filename = "alice_set"
    elif party == "bob":
        filename = "bob_set"
    else:
        filename = "output"

    if party == "output":
        file_path = "./output/" + filename
    else:
        file_path = "./input_sets/" + filename

    file_path = file_path.replace(".txt", "")
    file_path = file_path + '.txt'

    if not os.path.isdir("./input_sets"):
        os.mkdir("./input_sets")
    if not os.path.isdir("./output"):
        os.mkdir("./output")

    with open(file_path, mode='w+') as f:
        set_values = ' '.join([str(w) for w in party_set])
        f.write(set_values)
        f.close()

    return file_path


def main(
    party,
    circuit_path="circuits/sum.json",
    oblivious_transfer=True,
    print_mode="circuit"
):

    if party == "alice":
        number_of_int = int(input("[INPUT] What is the number of elements in the Alice's set?\nEnter it now: "))
        input_alice = list(int(element) for element in input("\n[INPUT] Now you need to enter the elements of the Alice's set!\nThe input format is: num1, num2, num3 ...\nEnter them now: ").strip().split(', '))[:number_of_int]
        if(sum(input_alice) > 255):
            print("[ERROR]: the sum of the entered numbers cannot be represented with 8 bits!")
        else:
            create_fileset("alice", input_alice)
            alice = Alice(circuit_path, input_alice, oblivious_transfer=oblivious_transfer, print_mode=print_mode)
            alice.start()

    elif party == "bob":
        number_of_int = int(input("[INPUT] What is the number of elements in the Bob's set?\nEnter it now: "))
        input_bob = list(int(element) for element in input("\n[INPUT] Now you need to enter the elements of the Bob's set!\nThe input format is: num1, num2, num3 ...\nEnter them now: ").strip().split(', '))[:number_of_int]
        if(sum(input_bob) > 255):
            print("[ERROR]: the sum of the entered numbers cannot be represented with 8 bits!")
        else:
            create_fileset("bob", input_bob)
            bob = Bob(input_bob, oblivious_transfer=oblivious_transfer)
            bob.listen()
    else:
        print("[ERROR]: Unknown party")


if __name__ == '__main__':

    def init():

        parser = argparse.ArgumentParser(description="Run Yao protocol.")
        parser.add_argument("party",
                            choices=["alice", "bob"],
                            help="the yao party to run")
        parser.add_argument(
            "-m",
            metavar="mode",
            choices=["circuit", "table"],
            default="circuit",
            help="the print mode for local tests (default 'circuit')")

        main(
            party=parser.parse_args().party,
            print_mode=parser.parse_args().m
        )

    init()
