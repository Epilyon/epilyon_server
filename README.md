# Epilyon server

Backend of the Epilyon app -- Keeping EPITA students organized

## Log format

epilyon.log format is `^\[([^ ]+)] \(([^ ]+)\) \[(\w+)( )?] \[((\w|::)+)] +\| (.+)` for each line (line start is `^\[`),
time group is the 2nd one, severity the 3rd one, category 5th one, message 7th one.