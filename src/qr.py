# The MIT License (MIT)

# Copyright (c) 2021 Tom J. Sun

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
import io
import qrcode
from ur.ur_encoder import UREncoder
from ur.ur_decoder import URDecoder
from ur.ur import UR

FORMAT_NONE  = const(0)
FORMAT_PMOFN = const(1)
FORMAT_UR    = const(2)

def get_size(qr_code):
	size = 0
	while qr_code[size] != '\n':
		size += 1
	return size

def data_len(data):
	if isinstance(data, UR):
		return len(data.cbor)
	return len(data)

def find_min_num_parts(data, max_width, format):
	num_parts = 1
	part_size = data_len(data) // num_parts
	while True:
		part = ''
		if format == FORMAT_PMOFN:
			part_number = 'p1of%d ' % num_parts
			part = part_number + data[0:part_size]
		elif format == FORMAT_UR:
			encoder = UREncoder(data, part_size, 1)
			part = encoder.next_part()
		if len(part) < 3918:
			code = qrcode.encode_to_string(part)
			if get_size(code) <= max_width:
				break
		num_parts += 1
		part_size = data_len(data) // num_parts
	return num_parts 

def to_qr_codes(data, max_width, format):
	if format == FORMAT_NONE:
		code = qrcode.encode_to_string(data)
		yield (code, 1)
	else:
		num_parts = find_min_num_parts(data, max_width, format)
		part_size = data_len(data) // num_parts
	
		if format == FORMAT_PMOFN:
			for i in range(num_parts):
				part_number = 'p%dof%d ' % (i + 1, num_parts)
				part = None
				if i == num_parts - 1:
					part = part_number + data[i * part_size:]
				else:
					part = part_number + data[i * part_size: i * part_size + part_size]
				code = qrcode.encode_to_string(part)
				yield (code, num_parts)
		elif format == FORMAT_UR:
			encoder = UREncoder(data, part_size, 1)
			while True:
				part = encoder.next_part()
				code = qrcode.encode_to_string(part)
				yield (code, encoder.fountain_encoder.seq_len())

def parse_pmofn_qr_part(data):
	of_index = data.index('of')
	space_index = data.index(' ')
	part_index = int(data[1:of_index])
	part_total = int(data[of_index+2:space_index])
	return data[space_index + 1:], part_index, part_total

def detect_format(data):
	format = FORMAT_NONE
	if data.startswith('p') and data.index('of') <= 5:
		format = FORMAT_PMOFN
	elif data.lower().startswith('ur:'):
		format = FORMAT_UR
	return format
	
class QRPartParser:
	def __init__(self):
		self.parts = {}
		self.total = -1
		self.format = None
		self.decoder = URDecoder()
  
	def parsed_count(self):
		if self.format == FORMAT_UR:
	  		return int(self.decoder.fountain_decoder.estimated_percent_complete() * self.total_count())
		return len(self.parts)
	
	def total_count(self):
		if self.format == FORMAT_UR:
	  		return self.decoder.fountain_decoder.expected_part_count()
		return self.total
	
	def parse(self, data):
		if self.format is None:
			self.format = detect_format(data)
   
		if self.format == FORMAT_NONE:
			self.parts[1] = data
			self.total = 1
		elif self.format == FORMAT_PMOFN:
			part, index, total = parse_pmofn_qr_part(data)
			self.parts[index] = part
			self.total = total
		elif self.format == FORMAT_UR:
			self.decoder.receive_part(data)

	def is_complete(self):
		if self.format == FORMAT_UR:
			return self.decoder.is_complete()
		return self.total != -1 and self.parsed_count() == self.total_count() and sum(self.parts.keys()) == sum(range(1, self.total+1))

	def result(self):
		if self.format == FORMAT_UR:
			if isinstance(self.decoder.result, UR):
				return UR(self.decoder.result.type, bytearray(self.decoder.result.cbor))
			return self.decoder.result
		code_buffer = io.StringIO('')
		for _, part in sorted(self.parts.items()):
			code_buffer.write(part)
		code = code_buffer.getvalue()
		code_buffer.close()
		return code
