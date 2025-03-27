import tkinter as tk
from tkinter import ttk, messagebox
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
#process code
class Process:
    def __init__(self, pid, allocation, max_demand):
        self.pid = pid
        self.allocation = allocation.copy()
        self.max_demand = max_demand.copy()
        self.need = [max_demand[i] - allocation[i] for i in range(len(allocation))]
        self.finished = False

    def calculate_need(self):
        self.need = [self.max_demand[i] - self.allocation[i] for i in range(len(self.allocation))]

class ResourceManager:
    def __init__(self, available, processes):
        self.available = available.copy()
        self.processes = processes
        self.resource_count = len(available)


    def is_safe_state(self):
        work = self.available.copy()
        finish = [p.finished for p in self.processes]
        
        while True:
            found = False
            for i, process in enumerate(self.processes):
                if not finish[i] and all(process.need[j] <= work[j] for j in range(self.resource_count)):
                    for j in range(self.resource_count):
                        work[j] += process.allocation[j]
                    finish[i] = True
                    found = True
            
            if not found:
                break
        
        return all(finish)
#updated algo
class BankersAlgorithm:
    def __init__(self, resource_manager):
        self.resource_manager = resource_manager

    def request_resources(self, pid, request):
        process = None
        process_index = -1
        for i, p in enumerate(self.resource_manager.processes):
            if p.pid == pid:
                process = p
                process_index = i
                break
        
        if process is None:
            return False
        
        if any(request[i] > process.need[i] for i in range(len(request))):
            return False
        
        if any(request[i] > self.resource_manager.available[i] for i in range(len(request))):
            return False
        
        old_available = self.resource_manager.available.copy()
        old_allocation = [p.allocation.copy() for p in self.resource_manager.processes]
        old_need = [p.need.copy() for p in self.resource_manager.processes]
        
        for i in range(len(request)):
            self.resource_manager.available[i] -= request[i]
            process.allocation[i] += request[i]
            process.need[i] -= request[i]
        
        is_safe = self.resource_manager.is_safe_state()
        
        if not is_safe:
            self.resource_manager.available = old_available
            for i, p in enumerate(self.resource_manager.processes):
                p.allocation = old_allocation[i]
                p.need = old_need[i]
            return False
        
        return True

class DeadlockDetector:
    def __init__(self, resource_manager):
        self.resource_manager = resource_manager

    def detect_deadlock(self):
        work = self.resource_manager.available.copy()
        finish = [p.finished for p in self.resource_manager.processes]
        deadlocked_processes = []
        
        changed = True
        while changed:
            changed = False
            for i, process in enumerate(self.resource_manager.processes):
                if not finish[i] and all(process.need[j] <= work[j] for j in range(self.resource_manager.resource_count)):
                    for j in range(self.resource_manager.resource_count):
                        work[j] += process.allocation[j]
                    finish[i] = True
                    changed = True
        
        deadlock = False
        for i, f in enumerate(finish):
            if not f:
                deadlock = True
                deadlocked_processes.append(self.resource_manager.processes[i].pid)
        
        return deadlocked_processes if deadlock else []

class DeadlockRecovery:
    def __init__(self, resource_manager):
        self.resource_manager = resource_manager

    def recover_termination(self, process_ids):
        for pid in process_ids:
            for process in self.resource_manager.processes:
                if process.pid == pid:
                    for j in range(self.resource_manager.resource_count):
                        self.resource_manager.available[j] += process.allocation[j]
                        process.allocation[j] = 0
                    process.finished = True
                    break

    def recover_preemption(self, pid, resources_to_preempt):
        for process in self.resource_manager.processes:
            if process.pid == pid:
                for j in range(len(resources_to_preempt)):
                    preempt_amount = min(resources_to_preempt[j], process.allocation[j])
                    process.allocation[j] -= preempt_amount
                    self.resource_manager.available[j] += preempt_amount
                process.calculate_need()
                break

class DeadlockToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Deadlock Prevention and Recovery Toolkit")
        
        self.initialize_sample_system()
        
        self.create_widgets()
        
        self.update_status()

    def initialize_sample_system(self):
        available = [3, 3, 2]
        processes = [
            Process("P0", [0, 1, 0], [7, 5, 3]),
            Process("P1", [2, 0, 0], [3, 2, 2]),
            Process("P2", [3, 0, 2], [9, 0, 2]),
            Process("P3", [2, 1, 1], [2, 2, 2]),
            Process("P4", [0, 0, 2], [4, 3, 3])
        ]
        
        self.resource_manager = ResourceManager(available, processes)
        self.bankers_algorithm = BankersAlgorithm(self.resource_manager)
        self.deadlock_detector = DeadlockDetector(self.resource_manager)
        self.deadlock_recovery = DeadlockRecovery(self.resource_manager)

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        status_frame = ttk.LabelFrame(main_frame, text="System Status", padding="10")
        status_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        self.status_text = tk.Text(status_frame, width=80, height=15, wrap=tk.NONE)
        self.status_text.grid(row=0, column=0)
        
        scroll_y = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.status_text.yview)
        scroll_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.status_text['yscrollcommand'] = scroll_y.set
        
        scroll_x = ttk.Scrollbar(status_frame, orient=tk.HORIZONTAL, command=self.status_text.xview)
        scroll_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        self.status_text['xscrollcommand'] = scroll_x.set
        
        graph_frame = ttk.LabelFrame(main_frame, text="Resource Allocation Graph", padding="10")
        graph_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        self.figure = plt.Figure(figsize=(8, 4), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=graph_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        control_frame = ttk.Frame(main_frame, padding="10")
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        ttk.Button(control_frame, text="Simulate Request", command=self.simulate_request_dialog).grid(row=0, column=0, padx=5)
        ttk.Button(control_frame, text="Create Deadlock", command=self.create_deadlock).grid(row=0, column=1, padx=5)
        ttk.Button(control_frame, text="Detect Deadlock", command=self.detect_deadlock).grid(row=0, column=2, padx=5)
        ttk.Button(control_frame, text="Recover (Termination)", command=self.recover_termination_dialog).grid(row=0, column=3, padx=5)
        ttk.Button(control_frame, text="Recover (Preemption)", command=self.recover_preemption_dialog).grid(row=0, column=4, padx=5)
        ttk.Button(control_frame, text="Reset System", command=self.reset_system).grid(row=0, column=5, padx=5)

    def update_status(self):
        status_text = "Current System Status:\n"
        status_text += f"Available Resources: {self.resource_manager.available}\n\n"
        
        status_text += "Processes:\n"
        status_text += f"{'PID':<5} {'Allocation':<15} {'Max':<15} {'Need':<15} {'Finished':<10}\n"
        for p in self.resource_manager.processes:
            status_text += f"{p.pid:<5} {str(p.allocation):<15} {str(p.max_demand):<15} {str(p.need):<15} {str(p.finished):<10}\n"
        
        status_text += f"\nSafety Status: {'SAFE' if self.resource_manager.is_safe_state() else 'UNSAFE'}\n"
        
        deadlocked = self.deadlock_detector.detect_deadlock()
        if deadlocked:
            status_text += f"\nDEADLOCK DETECTED! Affected processes: {deadlocked}\n"
        
        self.status_text.delete(1.0, tk.END)
        self.status_text.insert(tk.END, status_text)
        
        self.update_graph()

    def update_graph(self):
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        G = nx.DiGraph()
        
        for i, p in enumerate(self.resource_manager.processes):
            G.add_node(p.pid, type='process', color='lightblue')
        
        for i in range(len(self.resource_manager.available)):
            G.add_node(f"R{i}", type='resource', color='lightgreen')
        
        for p in self.resource_manager.processes:
            for i, alloc in enumerate(p.allocation):
                if alloc > 0:
                    G.add_edge(f"R{i}", p.pid, weight=alloc, color='black')
            
            for i, need in enumerate(p.need):
                if need > 0 and not p.finished:
                    G.add_edge(p.pid, f"R{i}", weight=need, color='red', style='dashed')
        
        pos = nx.spring_layout(G)
        node_colors = [G.nodes[n]['color'] for n in G.nodes()]
        edge_colors = [G.edges[e]['color'] for e in G.edges()]
        edge_styles = [G.edges[e].get('style', 'solid') for e in G.edges()]
        
        nx.draw_networkx_nodes(G, pos, node_color=node_colors, ax=ax)
        nx.draw_networkx_labels(G, pos, ax=ax)
        
        solid_edges = [(u, v) for (u, v, d) in G.edges(data=True) if d.get('style', 'solid') == 'solid']
        dashed_edges = [(u, v) for (u, v, d) in G.edges(data=True) if d.get('style', 'solid') == 'dashed']
        
        nx.draw_networkx_edges(G, pos, edgelist=solid_edges, edge_color='black', ax=ax)
        nx.draw_networkx_edges(G, pos, edgelist=dashed_edges, edge_color='red', style='dashed', ax=ax)
        
        edge_labels = {(u, v): d['weight'] for (u, v, d) in G.edges(data=True) if d['weight'] > 0}
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, ax=ax)
        
        ax.set_title("Resource Allocation Graph")
        self.canvas.draw()

    def simulate_request_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Simulate Resource Request")
        
        ttk.Label(dialog, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
        pid_entry = ttk.Entry(dialog)
        pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Resource Request (comma separated):").grid(row=1, column=0, padx=5, pady=5)
        request_entry = ttk.Entry(dialog)
        request_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def submit():
            try:
                pid = pid_entry.get()
                request = [int(x.strip()) for x in request_entry.get().split(",")]
                
                if len(request) != len(self.resource_manager.available):
                    messagebox.showerror("Error", f"Please enter exactly {len(self.resource_manager.available)} values")
                    return
                
                result = self.bankers_algorithm.request_resources(pid, request)
                if result:
                    messagebox.showinfo("Success", "Request granted. System remains in safe state.")
                else:
                    messagebox.showwarning("Warning", "Request denied. Would lead to unsafe state.")
                
                self.update_status()
                dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid input format")
        
        ttk.Button(dialog, text="Submit", command=submit).grid(row=2, column=0, columnspan=2, pady=10)

    def create_deadlock(self):
        available = [0, 0, 0]
        processes = [
            Process("P0", [1, 0, 0], [1, 1, 0]),
            Process("P1", [0, 1, 0], [0, 1, 1]),
            Process("P2", [0, 0, 1], [1, 0, 1]),
        ]
        
        self.resource_manager = ResourceManager(available, processes)
        self.bankers_algorithm = BankersAlgorithm(self.resource_manager)
        self.deadlock_detector = DeadlockDetector(self.resource_manager)
        self.deadlock_recovery = DeadlockRecovery(self.resource_manager)
        
        self.update_status()
        
        deadlocked = self.deadlock_detector.detect_deadlock()
        if deadlocked:
            messagebox.showinfo("Deadlock Created", f"Deadlock created successfully! Processes involved: {deadlocked}")

    def detect_deadlock(self):
        deadlocked = self.deadlock_detector.detect_deadlock()
        if deadlocked:
            messagebox.showwarning("Deadlock Detected", f"Deadlock detected! Processes involved: {deadlocked}")
        else:
            messagebox.showinfo("No Deadlock", "No deadlock detected in the system.")
        
        self.update_status()

    def recover_termination_dialog(self):
        deadlocked = self.deadlock_detector.detect_deadlock()
        if not deadlocked:
            messagebox.showinfo("No Deadlock", "No deadlock to recover from.")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Recover by Process Termination")
        
        ttk.Label(dialog, text="Select processes to terminate:").grid(row=0, column=0, padx=5, pady=5)
        
        process_vars = []
        for i, pid in enumerate(deadlocked):
            var = tk.BooleanVar(value=True)
            process_vars.append((pid, var))
            ttk.Checkbutton(dialog, text=pid, variable=var).grid(row=i+1, column=0, sticky=tk.W, padx=5, pady=2)
        
        def submit():
            to_terminate = [pid for pid, var in process_vars if var.get()]
            self.deadlock_recovery.recover_termination(to_terminate)
            self.update_status()
            dialog.destroy()
            messagebox.showinfo("Recovery Complete", f"Terminated processes: {to_terminate}")
        
        ttk.Button(dialog, text="Terminate Selected", command=submit).grid(row=len(deadlocked)+1, column=0, pady=10)

    def recover_preemption_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Recover by Resource Preemption")
        
        ttk.Label(dialog, text="Process ID:").grid(row=0, column=0, padx=5, pady=5)
        pid_entry = ttk.Entry(dialog)
        pid_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Resources to preempt (comma separated):").grid(row=1, column=0, padx=5, pady=5)
        request_entry = ttk.Entry(dialog)
        request_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def submit():
            try:
                pid = pid_entry.get()
                preempt = [int(x.strip()) for x in request_entry.get().split(",")]
                
                if len(preempt) != len(self.resource_manager.available):
                    messagebox.showerror("Error", f"Please enter exactly {len(self.resource_manager.available)} values")
                    return
                
                self.deadlock_recovery.recover_preemption(pid, preempt)
                self.update_status()
                dialog.destroy()
                messagebox.showinfo("Recovery Complete", f"Preempted resources from process {pid}")
            except ValueError:
                messagebox.showerror("Error", "Invalid input format")
        
        ttk.Button(dialog, text="Preempt Resources", command=submit).grid(row=2, column=0, columnspan=2, pady=10)

    def reset_system(self):
        self.initialize_sample_system()
        self.update_status()
        messagebox.showinfo("System Reset", "System has been reset to initial state.")

if __name__ == "__main__":
    root = tk.Tk()
    app = DeadlockToolkitGUI(root)
    root.mainloop()