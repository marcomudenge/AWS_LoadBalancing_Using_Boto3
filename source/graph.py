#get performance_metrics for performance_metrics.csv and plot a graph
#Data is InstanceID,data_points
#Data points is a list of dictionaries of timestamp: value (value beeing a % of CPU Utilization) (timestamp is a datetime string)
import pandas as pd
import matplotlib.pyplot as plt
import ast

# Read the performance_metrics.csv file
df = pd.read_csv('performance_metrics.csv')

# Process the data_points column to extract timestamps and values
def process_data_points(data_points):
    data_list = ast.literal_eval(data_points)
    timestamps = [list(item.keys())[0] for item in data_list]
    values = [list(item.values())[0] for item in data_list]
    return timestamps, values

# Prepare for plotting
for index, row in df.iterrows():
    timestamps, values = process_data_points(row['data_points'])
    
    # Convert timestamps to pandas datetime for sorting
    timestamps = pd.to_datetime(timestamps)
    
    # Create a DataFrame for sorting
    temp_df = pd.DataFrame({'Timestamp': timestamps, 'Values': values})
    
    # Sort by timestamp
    temp_df = temp_df.sort_values(by='Timestamp')
    
    # Plotting sorted data
    plt.plot(temp_df['Timestamp'], temp_df['Values'], marker='o', label=row['InstanceID'])

# Formatting the plot
plt.title('Instance Data Points Over Time')
plt.xlabel('Timestamp')
plt.ylabel('Values')
plt.xticks(rotation=45)
plt.legend()
plt.grid()
plt.tight_layout()

# Show the plot
plt.show()