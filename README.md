 Deadlock_toolkit


A Python-based toolkit for deadlock detection, prevention, and recovery using Banker's Algorithm and Resource Allocation Graphs.  

 Features  

- Deadlock Prevention using Banker’s Algorithm  
- Deadlock Detection using Resource Allocation Graphs  
- Deadlock Recovery via process termination or resource preemption  
- User-friendly Tkinter GUI  
- Visual representation using NetworkX and Matplotlib  

 Installation  

 Install Dependencies  

Before running the script, install the required libraries:  


pip install tkinter matplotlib networkx


 Clone the Repository : 


git clone https://github.com/divijeswara/Deadlock_toolkit.git
cd Deadlock_toolkit


Usage  

Run the Toolkit:  

Open VS Code Terminal or Command Prompt, then run:  


python deadlock_toolkit.py


 Input Process and Resource Details  

- Enter the number of processes and resources.  
- Define maximum claim, allocation, and available resources.  

Choose an Operation  

- Deadlock Detection: Check if a deadlock exists.  
- Deadlock Prevention: Apply Banker’s Algorithm.  
- Deadlock Recovery: Suggest process termination or resource preemption.  

Visualize Deadlock Status: 

The toolkit provides a graphical representation of process-resource allocation.  

How It Works  

1. Deadlock Detection:  
   - Creates a resource allocation graph.  
   - Uses cycle detection to check for deadlocks.  

2. Deadlock Prevention (Banker's Algorithm):  
   - Ensures that resource requests do not push the system into an unsafe state.  

3. Deadlock Recovery:  
   - Suggests process termination or resource preemption strategies.  

Example Input and Output  

Input  


Processes: 3  
Resources: 2  
Max Demand Matrix:  
  P0: [6, 4]  
  P1: [3, 2]  
  P2: [4, 3]  

Allocation Matrix:  
  P0: [2, 1]  
  P1: [1, 1]  
  P2: [2, 2]  

Available Resources: [2, 2]


Output  


Safe Sequence: P1 → P0 → P2  
Deadlock Not Detected!


Troubleshooting  

- GUI not opening? Ensure `tkinter` is installed (`pip install tk`).  
- No output after clicking buttons? Check console for errors and ensure correct input format.  


Contributing  

Feel free to submit pull requests for bug fixes and improvements.  

Contact  

For any questions or issues, reach out at divijeswara@gmail.com.  

