#include "gtest/gtest.h"
#include "apsi/tools/matrixview.h"
#include "apsi/tools/matrix.h"

#include <string>


namespace APSITests
{
	/**
	 * This class only exists to expose the resize method.
	 */
	template<class T>
	class MatrixViewTester : public apsi::MatrixView<T>
	{
	public:
		MatrixViewTester(T* data, apsi::u64 rows, apsi::u64 cols) :
			apsi::MatrixView<T>(data, rows, cols)
		{}

		void resize_test(T* data, apsi::u64 rows, apsi::u64 cols)
		{
			this->resize(data, rows, cols);
		}
	};

	/**
	 * This class only exists to expose the capacity method.
	 */
	template<class T>
	class MatrixTester : public apsi::Matrix<T>
	{
	public:
		MatrixTester(apsi::u64 rows, apsi::u64 cols)
			: apsi::Matrix<T>(rows, cols)
		{}

		apsi::u64 capacity_test() const
		{
			return this->capacity();
		}
	};


	TEST(MatrixViewTests, ConstructorTest)
	{
		int array[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
		apsi::MatrixView mv(array, 2, 5);

		ASSERT_EQ(6, mv(1, 0));
		ASSERT_EQ(8, mv(1, 2));

		apsi::MatrixView mv2(array, 5, 2);

		ASSERT_EQ(5, mv2(2, 0));
		ASSERT_EQ(10, mv2(4, 1));
	}

	TEST(MatrixViewTests, OperatorAssignTest)
	{
		int array[9] = { 9, 8, 7, 6, 5, 4, 3, 2, 1 };
		apsi::MatrixView mv(array, 3, 3);

		apsi::MatrixView<int> mv2;
		ASSERT_EQ((apsi::u64)0, mv2.rows());
		ASSERT_EQ((apsi::u64)0, mv2.columns());

		mv2 = mv;
		ASSERT_EQ((apsi::u64)3, mv2.rows());
		ASSERT_EQ((apsi::u64)3, mv2.columns());
		ASSERT_EQ(3, mv2(2, 0));
	}

	TEST(MatrixViewTests, OperatorBracketTest)
	{
		int array[6] = { 1, 2, 3, 4, 5, 6 };
		apsi::MatrixView mv(array, 2, 3);

		ASSERT_EQ(1, mv[0][0]);
		ASSERT_EQ(6, mv[1][2]);
		ASSERT_EQ(3, mv[0][2]);
		ASSERT_EQ(4, mv[1][0]);

		mv[1][2] = 7;
		ASSERT_EQ(7, mv[1][2]);
	}

	TEST(MatrixViewTests, OperatorParenTest)
	{
		std::string str = "Hello world!";
		apsi::MatrixView<char> mv(str.data(), 6, 2);

		ASSERT_EQ('H', mv(0, 0));
		ASSERT_EQ('!', mv(5, 1));
		ASSERT_EQ('l', mv(1, 0));

		// We can also use a single index to iterate
		ASSERT_EQ('H', mv(0));
		ASSERT_EQ('!', mv(11));
		ASSERT_EQ('l', mv(2));
		ASSERT_EQ('l', mv(3));
	}

	TEST(MatrixViewTests, SizeTest)
	{
		int array[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
		apsi::MatrixView mv(array, 2, 2);

		// The view _can_ have a smaller size than the actual data.
		ASSERT_EQ(4, mv[1][1]);
		ASSERT_EQ((apsi::u64)4, mv.size());
	}

	TEST(MatrixViewTests, ResizeTest)
	{
		int array[20] = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
						  11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
		MatrixViewTester<int> mv(array, 5, 4);

		ASSERT_EQ(1, mv(0, 0));
		ASSERT_EQ(5, mv(1, 0));
		ASSERT_EQ(9, mv(2, 0));
		ASSERT_EQ(13, mv(3, 0));
		ASSERT_EQ(20, mv(4, 3));

		mv.resize_test(array, 4, 5);

		ASSERT_EQ(1, mv(0, 0));
		ASSERT_EQ(5, mv(0, 4));
		ASSERT_EQ(9, mv(1, 3));
		ASSERT_EQ(13, mv(2, 2));
		ASSERT_EQ(20, mv(3, 4));
	}

	TEST(MatrixViewTests, IteratorTest)
	{
		int array[10] = { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10 };
		apsi::MatrixView mv(array, 5, 2);
		apsi::MatrixView mv2(array, 5, 1);

		apsi::u64 sum = 0;
		apsi::u64 sum2 = 0;

		for (auto& elem : mv)
		{
			sum += elem;
		}

		for (auto& elem : mv2)
		{
			sum2 += elem;
		}

		ASSERT_EQ((apsi::u64)55, sum);
		ASSERT_EQ((apsi::u64)15, sum2);
	}

	TEST(MatrixTests, ResizeTest)
	{
		MatrixTester<int> m(5, 5);
		for (apsi::u64 i = 0; i < m.rows(); i++)
		{
			for (apsi::u64 j = 0; j < m.columns(); j++)
			{
				m[i][j] = static_cast<int>(i * m.columns() + j + 1);
			}
		}

		ASSERT_EQ((apsi::u64)25, m.capacity_test());

		m.resize(10, 10);

		ASSERT_EQ((apsi::u64)10, m.rows());
		ASSERT_EQ((apsi::u64)10, m.columns());
		ASSERT_EQ((apsi::u64)100, m.size());
		ASSERT_EQ((apsi::u64)100, m.capacity_test());

		// Data should still be there, but in their new positions
		ASSERT_EQ(25, m(2, 4));
		ASSERT_EQ(10, m(0, 9));
		ASSERT_EQ(20, m(1, 9));

		// If we reduce the size the actual capacity should still be the same as before
		m.resize(2, 2);

		ASSERT_EQ(4, m(1, 1));
		ASSERT_EQ((apsi::u64)100, m.capacity_test());
	}
}
