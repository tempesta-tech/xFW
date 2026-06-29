
using SlotIdx = uint32_t;

template<std::size_t N, typename Derived>
class IndexedStatePool
{
public:
	enum class State : uint8_t {
		ReadyToUse,
		Active,
		Inactive,
	};

	SlotIdx allocate()
	{
		if (free_.empty())
			throw std::runtime_error("no free slots");

		SlotIdx idx = free_.back();
		free_.pop_back();

		state_[idx] = State::Active;
		static_cast<Derived*>(this)->on_allocate(idx);

		return idx;
	}

	void release(SlotIdx idx)
	{
		if (state_[idx] != State::Active)
			throw std::runtime_error("release of non-active slot");

		state_[idx] = State::Inactive;
		static_cast<Derived*>(this)->on_release(idx);
	}

	void reclaim_inactive()
	{
		for (SlotIdx i = 0; i < N; ++i) {
			if (state_[i] != State::Inactive)
				continue;

			static_cast<Derived*>(this)->on_reclaim(i);

			state_[i] = State::ReadyToUse;
			free_.push_back(i);
		}
	}

	bool is_active(SlotIdx i) const noexcept
	{
		return state_[i] == State::Active;
	}

protected:
	std::array<State, N> state_{};
	std::vector<Idx> free_;

	IndexedStatePool()
	{
		free_.reserve(N);
		for (Idx i = 0; i < N; ++i)
			free_.push_back(i);
	}
};