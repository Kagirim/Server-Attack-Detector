from datetime import datetime, date


class ServerAttackDetector:
    def __init__(self, file_path):
        self.durations = []
        with open(file_path) as input_file:
            self.data = input_file.readlines()

    def data_analyser(self):
        row_count = 0
        suspicious_lines = []
        all_rows = []
        timestamp_format = '%Y-%m-%d  %H:%M:%S.%f'
        for line in self.data:
            row_count += 1
            fields = line.strip()
            fields = fields.split(',')
            if row_count == 1:
                class_index = fields.index('class')
                proto_index = fields.index('Proto')
                duration_index = fields.index('Duration')
                timestamp_index = fields.index('Date first seen')
            else:
                if str(fields[class_index]) == 'suspicious':
                    if str(fields[proto_index].replace(' ', '')) == 'UDP':
                        if float(fields[duration_index].replace(' ', '')) < 1:
                            suspicious_lines.append(line)

        def detect():
            timestamp_list = []
            suspicious_rows = []
            for suspicious_line in suspicious_lines:
                suspicious_line = suspicious_line.split(',')
                timestamp_list.append(
                    datetime.strptime(suspicious_line[timestamp_index], timestamp_format))

            duration_list = [y - x for x, y in zip(timestamp_list[:-1], timestamp_list[1:])]
            counter = 0
            for duration in duration_list:
                counter += 1
                d_index = counter - 1
                duration = duration.total_seconds()
                if duration < 1:
                    suspicious_rows.append(suspicious_lines[d_index])

            positions = []
            for row in self.data:
                if row in suspicious_rows:
                    suspicious_pos = self.data.index(row) + 1
                    positions.append(suspicious_pos)
                    count_from_last = [position - positions[positions.index(position) - 1]
                                       if positions.index(position) != 0 else 0
                                       for position in positions]
                    for pos in positions:
                        a = pos
                        b = row
                    yield(a, b)

        detect()

        for i in detect():
            print(i)


detector = ServerAttackDetector('hw4testfile.csv')
detector.data_analyser()

