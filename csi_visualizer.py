import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.widgets import Button
import os
from datetime import datetime
import glob

class CSIVisualizer:
    def __init__(self):
        self.df = None
        self.current_file = None
        self.fig = None
        self.ax = None
        self.current_plot_type = 'time_series'
        
    def load_data(self, filename):
        """Load CSI data from CSV file"""
        try:
            self.df = pd.read_csv(filename)
            self.current_file = filename
            print(f"Successfully loaded {filename}")
            print(f"Data shape: {self.df.shape}")
            print(f"Time range: {self.df['timestamp'].iloc[0]} to {self.df['timestamp'].iloc[-1]}")
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False

    def initialize_plot(self):
        """Initialize the figure and axes"""
        if self.fig is None:
            self.fig = plt.figure(figsize=(15, 8))  # Increased figure width
        if self.ax is None:
            self.ax = self.fig.add_subplot(111)

    def plot_time_series(self):
        """Plot CSI data as time series"""
        if self.df is None:
            print("No data loaded")
            return

        self.initialize_plot()
        plt.clf()
        self.ax = self.fig.add_subplot(111)
        
        # Convert timestamp to datetime
        timestamps = pd.to_datetime(self.df['timestamp'])
        
        # Plot each subcarrier but only label some for the legend
        num_subcarriers = len(self.df.columns) - 1  # Exclude timestamp column
        legend_interval = max(1, num_subcarriers // 10)  # Show about 10 subcarriers in legend
        
        for i in range(1, len(self.df.columns)):
            line = self.ax.plot(timestamps, self.df.iloc[:, i], alpha=0.5)
            if (i-1) % legend_interval == 0:  # Only add label for some subcarriers
                line[0].set_label(f'Subcarrier {i-1}')
        
        self.ax.set_title('CSI Amplitude Time Series')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Amplitude')
        
        # Adjust legend position and size
        legend = self.ax.legend(bbox_to_anchor=(1.02, 1), 
                              loc='upper left', 
                              ncol=1,  # Single column legend
                              fontsize='small',  # Smaller font
                              title='Selected Subcarriers')
        legend.get_title().set_fontsize('small')
        
        self.ax.grid(True)
        # Adjust layout to accommodate legend
        plt.subplots_adjust(right=0.85)  # Make room for legend
        plt.draw()

    def plot_heatmap(self):
        """Plot CSI data as a heatmap"""
        if self.df is None:
            print("No data loaded")
            return

        self.initialize_plot()
        plt.clf()
        self.ax = self.fig.add_subplot(111)
        
        # Prepare data for heatmap
        data = self.df.iloc[:, 1:].values.T  # Exclude timestamp column
        
        # Create heatmap
        im = self.ax.imshow(data, aspect='auto', cmap='viridis')
        
        # Add colorbar
        plt.colorbar(im, ax=self.ax, label='Amplitude')
        
        self.ax.set_title('CSI Amplitude Heatmap')
        self.ax.set_xlabel('Time Index')
        self.ax.set_ylabel('Subcarrier Index')
        plt.tight_layout()
        plt.draw()

    def plot_statistics(self):
        """Plot statistical analysis of CSI data"""
        if self.df is None:
            print("No data loaded")
            return

        self.initialize_plot()
        plt.clf()
        self.ax = self.fig.add_subplot(111)
        
        # Calculate statistics
        means = self.df.iloc[:, 1:].mean()
        stds = self.df.iloc[:, 1:].std()
        
        # Create bar plot
        x = np.arange(len(means))
        width = 0.35
        
        self.ax.bar(x - width/2, means, width, label='Mean')
        self.ax.bar(x + width/2, stds, width, label='Standard Deviation')
        
        self.ax.set_title('CSI Statistics per Subcarrier')
        self.ax.set_xlabel('Subcarrier Index')
        self.ax.set_ylabel('Value')
        self.ax.legend()
        self.ax.grid(True)
        plt.tight_layout()
        plt.draw()

    def next_plot(self, event):
        """Switch to next plot type"""
        plot_types = ['time_series', 'heatmap', 'statistics']
        current_index = plot_types.index(self.current_plot_type)
        self.current_plot_type = plot_types[(current_index + 1) % len(plot_types)]
        self.update_plot()

    def update_plot(self):
        """Update the current plot based on plot type"""
        if self.current_plot_type == 'time_series':
            self.plot_time_series()
        elif self.current_plot_type == 'heatmap':
            self.plot_heatmap()
        elif self.current_plot_type == 'statistics':
            self.plot_statistics()

    def run(self):
        """Main function to run the visualizer"""
        # Find all CSI data files
        csi_files = glob.glob('csi_data_*.csv')
        if not csi_files:
            print("No CSI data files found in the current directory")
            return

        # Create figure and buttons
        self.fig = plt.figure(figsize=(15, 8))  # Increased figure width
        ax_button = plt.axes([0.81, 0.01, 0.1, 0.04])
        button = Button(ax_button, 'Next Plot')

        # Connect button to callback
        button.on_clicked(self.next_plot)

        # Load the most recent file by default
        latest_file = max(csi_files, key=os.path.getctime)
        if self.load_data(latest_file):
            self.plot_time_series()
            plt.show()

def main():
    visualizer = CSIVisualizer()
    visualizer.run()

if __name__ == '__main__':
    main() 